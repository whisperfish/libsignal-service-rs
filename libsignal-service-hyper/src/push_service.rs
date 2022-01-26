use std::{io::Read, time::Duration};

use bytes::{Buf, Bytes};
use futures::{FutureExt, StreamExt, TryStreamExt};
use headers::{Authorization, HeaderMapExt};
use hyper::{
    client::HttpConnector,
    header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
    Body, Client, Method, Request, Response, StatusCode,
};
use hyper_rustls::HttpsConnector;
use hyper_timeout::TimeoutConnector;
use libsignal_service::{
    configuration::*, messagepipe::WebSocketService, prelude::ProtobufMessage,
    push_service::*, MaybeSend,
};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;

use crate::websocket::TungsteniteWebSocket;

#[derive(Clone)]
pub struct HyperPushService {
    cfg: ServiceConfiguration,
    user_agent: String,
    credentials: Option<HttpAuth>,
    client: Client<TimeoutConnector<HttpsConnector<HttpConnector>>>,
}

#[derive(Debug)]
struct RequestBody {
    contents: Vec<u8>,
    content_type: String,
}

impl HyperPushService {
    pub fn new(
        cfg: impl Into<ServiceConfiguration>,
        credentials: Option<ServiceCredentials>,
        user_agent: String,
    ) -> Self {
        let cfg = cfg.into();
        let tls_config = Self::tls_config(&cfg);

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::from((http, tls_config));

        // as in Signal-Android
        let mut timeout_connector = TimeoutConnector::new(https);
        timeout_connector.set_connect_timeout(Some(Duration::from_secs(10)));
        timeout_connector.set_read_timeout(Some(Duration::from_secs(65)));
        timeout_connector.set_write_timeout(Some(Duration::from_secs(65)));

        let client: Client<_, hyper::Body> =
            Client::builder().build(timeout_connector);

        Self {
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
            user_agent,
        }
    }

    fn tls_config(cfg: &ServiceConfiguration) -> rustls::ClientConfig {
        // This will fail to compile against rustls 0.20, see service-actix push_service get_client
        let mut tls_config = rustls::ClientConfig::new();
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls_config
            .root_store
            .add_pem_file(&mut std::io::Cursor::new(
                cfg.certificate_authority.clone(),
            ))
            .expect("invalid TLS certificate authority");
        tls_config
    }

    async fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        path: impl AsRef<str>,
        credentials_override: HttpAuthOverride,
        body: Option<RequestBody>,
    ) -> Result<Response<Body>, ServiceError> {
        let url = self.cfg.base_url(endpoint).join(path.as_ref())?;
        log::debug!("HTTP request {} {}", method, url);
        let mut builder = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(USER_AGENT, &self.user_agent);

        match credentials_override {
            HttpAuthOverride::NoOverride => {
                if let Some(HttpAuth { username, password }) =
                    self.credentials.as_ref()
                {
                    builder
                        .headers_mut()
                        .unwrap()
                        .typed_insert(Authorization::basic(username, password));
                }
            },
            HttpAuthOverride::Identified(HttpAuth { username, password }) => {
                builder
                    .headers_mut()
                    .unwrap()
                    .typed_insert(Authorization::basic(&username, &password));
            },
            HttpAuthOverride::Unidentified => (),
        };

        let request = if let Some(RequestBody {
            contents,
            content_type,
        }) = body
        {
            builder
                .header(CONTENT_LENGTH, contents.len() as u64)
                .header(CONTENT_TYPE, content_type)
                .body(Body::from(contents))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };

        let mut response = self.client.request(request).await.map_err(|e| {
            ServiceError::SendError {
                reason: e.to_string(),
            }
        })?;

        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NO_CONTENT => Ok(response),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(ServiceError::Unauthorized)
            },
            StatusCode::PAYLOAD_TOO_LARGE => {
                // This is 413 and means rate limit exceeded for Signal.
                Err(ServiceError::RateLimitExceeded)
            },
            StatusCode::CONFLICT => {
                let mismatched_devices =
                    Self::json(&mut response).await.map_err(|e| {
                        log::error!(
                            "Failed to decode HTTP 409 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: StatusCode::CONFLICT.as_u16(),
                        }
                    })?;
                Err(ServiceError::MismatchedDevicesException(
                    mismatched_devices,
                ))
            },
            StatusCode::GONE => {
                let stale_devices =
                    Self::json(&mut response).await.map_err(|e| {
                        log::error!(
                            "Failed to decode HTTP 410 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: StatusCode::GONE.as_u16(),
                        }
                    })?;
                Err(ServiceError::StaleDevices(stale_devices))
            },
            // XXX: fill in rest from PushServiceSocket
            code => {
                log::trace!(
                    "Unhandled response with body: {}",
                    Self::text(&mut response).await?
                );
                Err(ServiceError::UnhandledResponseCode {
                    http_code: code.as_u16(),
                })
            },
        }
    }

    async fn json<T>(response: &mut Response<Body>) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let body = hyper::body::aggregate(response).await.map_err(|e| {
            ServiceError::ResponseError {
                reason: format!(
                    "failed to aggregate HTTP response body: {}",
                    e
                ),
            }
        })?;

        serde_json::from_reader(body.reader()).map_err(|e| {
            ServiceError::JsonDecodeError {
                reason: e.to_string(),
            }
        })
    }

    async fn protobuf<M>(
        response: &mut Response<Body>,
    ) -> Result<M, ServiceError>
    where
        M: ProtobufMessage + Default,
    {
        let body = hyper::body::aggregate(response).await.map_err(|e| {
            ServiceError::ResponseError {
                reason: format!(
                    "failed to aggregate HTTP response body: {}",
                    e
                ),
            }
        })?;

        M::decode(body).map_err(ServiceError::ProtobufDecodeError)
    }

    async fn text(
        response: &mut Response<Body>,
    ) -> Result<String, ServiceError> {
        let body = hyper::body::aggregate(response).await.map_err(|e| {
            ServiceError::ResponseError {
                reason: format!(
                    "failed to aggregate HTTP response body: {}",
                    e
                ),
            }
        })?;
        let mut text = String::new();
        body.reader().read_to_string(&mut text).map_err(|e| {
            ServiceError::ResponseError {
                reason: format!("failed to read HTTP response body: {}", e),
            }
        })?;
        Ok(text)
    }
}

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
impl PushService for HyperPushService {
    // This is in principle known at compile time, but long to write out.
    type ByteStream = Box<dyn futures::io::AsyncRead + Unpin>;
    type WebSocket = TungsteniteWebSocket;

    async fn get_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let mut response = self
            .request(Method::GET, service, path, credentials_override, None)
            .await?;

        Self::json(&mut response).await
    }

    async fn delete_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let mut response = self
            .request(
                Method::DELETE,
                service,
                path,
                HttpAuthOverride::NoOverride,
                None,
            )
            .await?;

        Self::json(&mut response).await
    }

    async fn put_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: MaybeSend + Serialize,
    {
        let json = serde_json::to_vec(&value).map_err(|e| {
            ServiceError::JsonDecodeError {
                reason: e.to_string(),
            }
        })?;

        let mut response = self
            .request(
                Method::PUT,
                service,
                path,
                credentials_override,
                Some(RequestBody {
                    contents: json,
                    content_type: "application/json".into(),
                }),
            )
            .await?;

        Self::json(&mut response).await
    }

    async fn get_protobuf<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        T: Default + libsignal_service::prelude::ProtobufMessage,
    {
        let mut response = self
            .request(Method::GET, service, path, credentials_override, None)
            .await?;

        Self::protobuf(&mut response).await
    }

    async fn put_protobuf<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        value: S,
    ) -> Result<D, ServiceError>
    where
        D: Default + libsignal_service::prelude::ProtobufMessage,
        S: Sized + libsignal_service::prelude::ProtobufMessage,
    {
        let protobuf = value.encode_to_vec();

        let mut response = self
            .request(
                Method::PUT,
                service,
                path,
                HttpAuthOverride::NoOverride,
                Some(RequestBody {
                    contents: protobuf,
                    content_type: "application/x-protobuf".into(),
                }),
            )
            .await?;

        Self::protobuf(&mut response).await
    }

    async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        let response = self
            .request(
                Method::GET,
                Endpoint::Cdn(cdn_id),
                path,
                HttpAuthOverride::Unidentified, // CDN requests are always without authentication
                None,
            )
            .await?;

        Ok(Box::new(
            response
                .into_body()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
                .into_async_read(),
        ))
    }

    async fn post_to_cdn0<'s, C: std::io::Read + Send + 's>(
        &mut self,
        path: &str,
        value: &[(&str, &str)],
        file: Option<(&str, &'s mut C)>,
    ) -> Result<(), ServiceError> {
        let mut form = mpart_async::client::MultipartRequest::default();

        // mpart-async has a peculiar ordering of the form items,
        // and Amazon S3 expects them in a very specific order (i.e., the file contents should
        // go last.
        //
        // mpart-async uses a VecDeque internally for ordering the fields in the order given.
        //
        // https://github.com/cetra3/mpart-async/issues/16

        for &(k, v) in value {
            form.add_field(k, v);
        }

        if let Some((filename, file)) = file {
            // XXX Actix doesn't cope with none-'static lifetimes
            // https://docs.rs/actix-web/3.2.0/actix_web/body/enum.Body.html
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .expect("infallible Read instance");
            form.add_stream(
                "file",
                filename,
                "application/octet-stream",
                futures::future::ok::<_, ()>(Bytes::from(buf)).into_stream(),
            );
        }

        let content_type =
            format!("multipart/form-data; boundary={}", form.get_boundary());

        // XXX Amazon S3 needs the Content-Length, but we don't know it without depleting the whole
        // stream. Sadly, Content-Length != contents.len(), but should include the whole form.
        let mut body_contents = vec![];
        while let Some(b) = form.next().await {
            // Unwrap, because no error type was used above
            body_contents.extend(b.unwrap());
        }
        log::trace!(
            "Sending PUT with Content-Type={} and length {}",
            content_type,
            body_contents.len()
        );

        let response = self
            .request(
                Method::POST,
                Endpoint::Cdn(0),
                path,
                HttpAuthOverride::NoOverride,
                Some(RequestBody {
                    contents: body_contents,
                    content_type,
                }),
            )
            .await?;

        log::debug!("AwcPushService::PUT response: {:?}", response);

        Ok(())
    }

    async fn ws(
        &mut self,
        path: &str,
        credentials: Option<ServiceCredentials>,
    ) -> Result<
        (
            Self::WebSocket,
            <Self::WebSocket as WebSocketService>::Stream,
        ),
        ServiceError,
    > {
        Ok(TungsteniteWebSocket::with_tls_config(
            Self::tls_config(&self.cfg),
            self.cfg.base_url(Endpoint::Service),
            path,
            credentials.as_ref(),
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use libsignal_service::configuration::SignalServers;

    #[test]
    fn create_clients() {
        let configs = &[SignalServers::Staging, SignalServers::Production];

        for cfg in configs {
            let _ = super::HyperPushService::new(
                cfg,
                None,
                "libsignal-service test".to_string(),
            );
        }
    }
}
