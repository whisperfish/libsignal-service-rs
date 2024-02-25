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
    configuration::*, prelude::ProtobufMessage, push_service::*,
    websocket::SignalWebSocket, MaybeSend,
};
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing_futures::Instrument;

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

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build();

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
        let mut cert_bytes = std::io::Cursor::new(&cfg.certificate_authority);
        let roots = rustls_pemfile::certs(&mut cert_bytes);

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.add_parsable_certificates(
            roots.map(|c| c.expect("parsable PEM files")),
        );

        rustls::ClientConfig::builder()
            .with_root_certificates(root_certs)
            .with_no_client_auth()
    }

    #[tracing::instrument(skip(self, path, body), fields(path = %path.as_ref()))]
    async fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        path: impl AsRef<str>,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
        body: Option<RequestBody>,
    ) -> Result<Response<Body>, ServiceError> {
        let url = self.cfg.base_url(endpoint).join(path.as_ref())?;
        let mut builder = Request::builder()
            .method(method)
            .uri(url.as_str())
            .header(USER_AGENT, &self.user_agent);

        for (header, value) in additional_headers {
            builder = builder.header(*header, *value);
        }

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
            StatusCode::NOT_FOUND => {
                // This is 404 and means that e.g. recipient is not registered
                Err(ServiceError::NotFoundError)
            },
            StatusCode::PAYLOAD_TOO_LARGE => {
                // This is 413 and means rate limit exceeded for Signal.
                Err(ServiceError::RateLimitExceeded)
            },
            StatusCode::CONFLICT => {
                let mismatched_devices =
                    Self::json(&mut response).await.map_err(|e| {
                        tracing::error!(
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
                        tracing::error!(
                            "Failed to decode HTTP 410 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: StatusCode::GONE.as_u16(),
                        }
                    })?;
                Err(ServiceError::StaleDevices(stale_devices))
            },
            StatusCode::PRECONDITION_REQUIRED => {
                let proof_required =
                    Self::json(&mut response).await.map_err(|e| {
                        tracing::error!(
                            "Failed to decode HTTP 428 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: StatusCode::PRECONDITION_REQUIRED
                                .as_u16(),
                        }
                    })?;
                Err(ServiceError::ProofRequiredError(proof_required))
            },
            // XXX: fill in rest from PushServiceSocket
            code => {
                tracing::trace!(
                    "Unhandled response {} with body: {}",
                    code.as_u16(),
                    Self::text(&mut response).await?,
                );
                Err(ServiceError::UnhandledResponseCode {
                    http_code: code.as_u16(),
                })
            },
        }
    }

    #[tracing::instrument(skip(response), fields(status = %response.status()))]
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

        if body.has_remaining() {
            serde_json::from_reader(body.reader())
        } else {
            serde_json::from_value(serde_json::Value::Null)
        }
        .map_err(|e| ServiceError::JsonDecodeError {
            reason: e.to_string(),
        })
    }

    #[tracing::instrument(skip(response), fields(status = %response.status()))]
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

    #[tracing::instrument(skip(response), fields(status = %response.status()))]
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
    type ByteStream = Box<dyn futures::io::AsyncRead + Send + Unpin>;

    #[tracing::instrument(skip(self))]
    async fn get_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let mut response = self
            .request(
                Method::GET,
                service,
                path,
                additional_headers,
                credentials_override,
                None,
            )
            .await?;

        Self::json(&mut response).await
    }

    #[tracing::instrument(skip(self))]
    async fn delete_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let mut response = self
            .request(
                Method::DELETE,
                service,
                path,
                additional_headers,
                HttpAuthOverride::NoOverride,
                None,
            )
            .await?;

        Self::json(&mut response).await
    }

    #[tracing::instrument(skip(self, value))]
    async fn put_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
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
                additional_headers,
                credentials_override,
                Some(RequestBody {
                    contents: json,
                    content_type: "application/json".into(),
                }),
            )
            .await?;

        Self::json(&mut response).await
    }

    #[tracing::instrument(skip(self, value))]
    async fn patch_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
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
                Method::PATCH,
                service,
                path,
                additional_headers,
                credentials_override,
                Some(RequestBody {
                    contents: json,
                    content_type: "application/json".into(),
                }),
            )
            .await?;

        Self::json(&mut response).await
    }

    #[tracing::instrument(skip(self, value))]
    async fn post_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
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
                Method::POST,
                service,
                path,
                additional_headers,
                credentials_override,
                Some(RequestBody {
                    contents: json,
                    content_type: "application/json".into(),
                }),
            )
            .await?;

        Self::json(&mut response).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_protobuf<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        T: Default + libsignal_service::prelude::ProtobufMessage,
    {
        let mut response = self
            .request(
                Method::GET,
                service,
                path,
                additional_headers,
                credentials_override,
                None,
            )
            .await?;

        Self::protobuf(&mut response).await
    }

    #[tracing::instrument(skip(self, value))]
    async fn put_protobuf<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
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
                additional_headers,
                HttpAuthOverride::NoOverride,
                Some(RequestBody {
                    contents: protobuf,
                    content_type: "application/x-protobuf".into(),
                }),
            )
            .await?;

        Self::protobuf(&mut response).await
    }

    #[tracing::instrument(skip(self))]
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
                &[],
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

    #[tracing::instrument(skip(self, value, file), fields(file = file.as_ref().map(|_| "")))]
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
        tracing::trace!(
            "Sending PUT with Content-Type={} and length {}",
            content_type,
            body_contents.len()
        );

        let response = self
            .request(
                Method::POST,
                Endpoint::Cdn(0),
                path,
                &[],
                HttpAuthOverride::NoOverride,
                Some(RequestBody {
                    contents: body_contents,
                    content_type,
                }),
            )
            .await?;

        tracing::debug!("HyperPushService::PUT response: {:?}", response);

        Ok(())
    }

    async fn ws(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket, ServiceError> {
        let span = tracing::debug_span!("websocket");
        let (ws, stream) = TungsteniteWebSocket::with_tls_config(
            Self::tls_config(&self.cfg),
            self.cfg.base_url(Endpoint::Service),
            path,
            additional_headers,
            credentials.as_ref(),
        )
        .instrument(span.clone())
        .await?;
        let (ws, task) =
            SignalWebSocket::from_socket(ws, stream, keepalive_path.to_owned());
        let task = task.instrument(span);
        #[cfg(feature = "unsend-futures")]
        tokio::task::spawn_local(task);
        #[cfg(not(feature = "unsend-futures"))]
        tokio::task::spawn(task);
        Ok(ws)
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};
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

    #[test]
    fn serde_json_from_empty_reader() {
        // This fails, so we have handle empty response body separately in HyperPushService::json()
        let bytes: Bytes = "".into();
        assert!(
            serde_json::from_reader::<bytes::buf::Reader<Bytes>, String>(
                bytes.reader()
            )
            .is_err()
        );
    }

    #[test]
    fn serde_json_form_empty_vec() {
        // If we're trying to send and empty payload, serde_json must be able to make a Vec out of it
        assert!(serde_json::to_vec(b"").is_ok());
    }
}
