use std::{sync::Arc, time::Duration};

use awc::{
    error::PayloadError, http::StatusCode, Client, ClientResponse, Connector,
};
use bytes::Bytes;
use futures::prelude::*;
use libsignal_service::{
    configuration::*, messagepipe::WebSocketService, push_service::*,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::websocket::AwcWebSocket;

#[derive(Clone)]
pub struct AwcPushService {
    cfg: ServiceConfiguration,
    base_url: Url,
    client: awc::Client,
}

#[async_trait::async_trait(?Send)]
impl PushService for AwcPushService {
    // This is in principle known at compile time, but long to write out.
    type ByteStream = Box<dyn futures::io::AsyncRead + Unpin>;
    type WebSocket = AwcWebSocket;

    async fn get<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        // In principle, we should be using http::uri::Uri,
        // but that doesn't seem like an owned type where we can do this kind of
        // constructions on.
        // https://docs.rs/http/0.2.1/http/uri/struct.Uri.html
        let url = self.base_url.join(path).expect("valid url");

        log::debug!("AwcPushService::get({:?})", url);
        use awc::error::{ConnectError, SendRequestError};
        let mut response = self.client.get(url.as_str()).send().await.map_err(
            |e| match e {
                SendRequestError::Connect(ConnectError::Timeout) => {
                    ServiceError::Timeout {
                        reason: e.to_string(),
                    }
                }
                _ => ServiceError::SendError {
                    reason: e.to_string(),
                },
            },
        )?;

        log::debug!("AwcPushService::get response: {:?}", response);

        Self::from_response(&mut response).await?;

        // In order to debug the output, we collect the whole response.
        // The actix-web api is meant to used as a streaming deserializer,
        // so we have this little awkward switch.
        //
        // This is also the reason we depend directly on serde_json, however
        // actix already imports that anyway.
        if log::log_enabled!(log::Level::Debug) {
            let text = response.body().await.map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })?;
            log::debug!("GET response: {:?}", String::from_utf8_lossy(&text));
            serde_json::from_slice(&text).map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })
        } else {
            response
                .json()
                .await
                .map_err(|e| ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                })
        }
    }

    /// Deletes a resource through the HTTP DELETE verb.
    async fn delete<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        // In principle, we should be using http::uri::Uri,
        // but that doesn't seem like an owned type where we can do this kind of
        // constructions on.
        // https://docs.rs/http/0.2.1/http/uri/struct.Uri.html
        let url = self.base_url.join(path).expect("valid url");

        log::debug!("AwcPushService::delete({:?})", url);
        use awc::error::{ConnectError, SendRequestError};
        let mut response =
            self.client.delete(url.as_str()).send().await.map_err(
                |e| match e {
                    SendRequestError::Connect(ConnectError::Timeout) => {
                        ServiceError::Timeout {
                            reason: e.to_string(),
                        }
                    }
                    _ => ServiceError::SendError {
                        reason: e.to_string(),
                    },
                },
            )?;

        log::debug!("AwcPushService::delete response: {:?}", response);

        Self::from_response(&mut response).await?;

        // In order to debug the output, we collect the whole response.
        // The actix-web api is meant to used as a streaming deserializer,
        // so we have this little awkward switch.
        //
        // This is also the reason we depend directly on serde_json, however
        // actix already imports that anyway.
        if log::log_enabled!(log::Level::Debug) {
            let text = response.body().await.map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })?;
            log::debug!(
                "DELETE response: {:?}",
                String::from_utf8_lossy(&text)
            );
            serde_json::from_slice(&text).map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })
        } else {
            response
                .json()
                .await
                .map_err(|e| ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                })
        }
    }

    async fn put<D, S>(
        &mut self,
        path: &str,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize,
    {
        // In principle, we should be using http::uri::Uri,
        // but that doesn't seem like an owned type where we can do this kind of
        // constructions on.
        // https://docs.rs/http/0.2.1/http/uri/struct.Uri.html
        let url = self.base_url.join(path).expect("valid url");

        log::debug!("AwcPushService::put({:?})", url);
        let mut response = self
            .client
            .put(url.as_str())
            .send_json(&value)
            .await
            .map_err(|e| ServiceError::SendError {
                reason: e.to_string(),
            })?;

        log::debug!("AwcPushService::put response: {:?}", response);

        Self::from_response(&mut response).await?;

        // In order to debug the output, we collect the whole response.
        // The actix-web api is meant to used as a streaming deserializer,
        // so we have this little awkward switch.
        //
        // This is also the reason we depend directly on serde_json, however
        // actix already imports that anyway.
        if log::log_enabled!(log::Level::Debug) {
            let text = response.body().await.map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })?;
            log::debug!("PUT response: {:?}", String::from_utf8_lossy(&text));
            serde_json::from_slice(&text).map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })
        } else {
            response
                .json()
                .await
                .map_err(|e| ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                })
        }
    }

    async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        use futures::stream::TryStreamExt;

        let url = Url::parse(&self.cfg.cdn_urls[&cdn_id])
            .expect("valid cdn base url")
            .join(path)
            .expect("valid CDN path");

        log::debug!("AwcPushService::get_stream({:?})", url);
        let mut response =
            self.client.get(url.as_str()).send().await.map_err(|e| {
                ServiceError::SendError {
                    reason: e.to_string(),
                }
            })?;

        log::debug!("AwcPushService::get_stream response: {:?}", response);

        Self::from_response(&mut response).await?;

        Ok(Box::new(
            response
                .map_err(|e| {
                    use awc::error::PayloadError;
                    match e {
                        PayloadError::Io(e) => e,
                        other => std::io::Error::new(
                            std::io::ErrorKind::Other,
                            other,
                        ),
                    }
                })
                .into_async_read(),
        ))
    }

    async fn post_to_cdn0<'s, C: std::io::Read + Send + 's>(
        &mut self,
        path: &str,
        value: &[(&str, &str)],
        file: Option<(&str, &'s mut C)>,
    ) -> Result<(), ServiceError> {
        let url = Url::parse(&self.cfg.cdn_urls[&0])
            .expect("valid cdn base url")
            .join(path)
            .expect("valid CDN path");

        log::debug!("AwcPushService::post_to_cdn({:?})", url);
        let client = self.client.post(url.as_str());

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
                &filename,
                "application/octet-stream",
                futures::future::ok::<_, ()>(Bytes::from(buf)).into_stream(),
            );
        }

        let content_type =
            format!("multipart/form-data; boundary={}", form.get_boundary());

        // XXX Amazon S3 needs the Content-Length, but we don't know it without depleting the whole
        // stream.  Sadly, Content-Length != contents.len(), but should include the whole form.
        let mut body_contents = vec![];
        use futures::stream::StreamExt;
        while let Some(b) = form.next().await {
            // Unwrap, because no error type was used above
            body_contents.extend(b.unwrap());
        }
        log::trace!(
            "Sending PUT with Content-Type={} and length {}",
            content_type,
            body_contents.len()
        );

        let mut response = client
            .content_type(&content_type)
            .content_length(body_contents.len() as u64)
            .send_body(body_contents)
            .await
            .map_err(|e| ServiceError::SendError {
                reason: e.to_string(),
            })?;

        log::debug!("AwcPushService::put response: {:?}", response);

        Self::from_response(&mut response).await?;

        Ok(())
    }

    async fn ws(
        &mut self,
        path: &str,
        credentials: Option<Credentials>,
    ) -> Result<
        (
            Self::WebSocket,
            <Self::WebSocket as WebSocketService>::Stream,
        ),
        ServiceError,
    > {
        Ok(AwcWebSocket::with_client(
            &mut self.client,
            &self.base_url,
            path,
            credentials.as_ref(),
        )
        .await?)
    }
}

/// Creates a `awc::Client` with usable default settings:
/// Creates a default `awc::Client`.
///
/// Creates a `awc::Client` with usable default settings:
/// * certificate authority from the `ServiceConfiguration`
/// * 10s timeout on TCP connection
/// * 65s timeout on HTTP request
/// * provided user-agent
pub fn get_client(
    cfg: &ServiceConfiguration,
    credentials: Option<Credentials>,
    user_agent: &str,
) -> Client {
    let mut ssl_config = rustls::ClientConfig::new();
    ssl_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    ssl_config
        .root_store
        .add_pem_file(&mut std::io::Cursor::new(
            cfg.certificate_authority.clone(),
        ))
        .unwrap();
    let connector = Connector::new()
        .rustls(Arc::new(ssl_config))
        .timeout(Duration::from_secs(10)) // https://github.com/actix/actix-web/issues/1047
        .finish();
    let mut client = awc::ClientBuilder::new()
        .connector(connector)
        .header("X-Signal-Agent", user_agent)
        .timeout(Duration::from_secs(65)); // as in Signal-Android

    if let Some(credentials) = credentials {
        if let Some((ident, pass)) = credentials.authorization() {
            client = client.basic_auth(ident, Some(pass));
        }
    };

    client.finish()
}

impl AwcPushService {
    /// Creates a new AwcPushService
    ///
    /// Panics on invalid service url.
    pub fn new(
        cfg: ServiceConfiguration,
        credentials: Option<Credentials>,
        user_agent: &str,
    ) -> Self {
        let base_url =
            Url::parse(&cfg.service_urls[0]).expect("valid service url");

        let client = get_client(&cfg, credentials, user_agent);

        Self {
            cfg,
            base_url,
            client,
        }
    }

    async fn from_response<S>(
        response: &mut ClientResponse<S>,
    ) -> Result<(), ServiceError>
    where
        S: Stream<Item = Result<Bytes, PayloadError>> + Unpin,
    {
        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(ServiceError::Unauthorized)
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                // This is 413 and means rate limit exceeded for Signal.
                Err(ServiceError::RateLimitExceeded)
            }
            StatusCode::CONFLICT => {
                let mismatched_devices =
                    response.json().await.map_err(|e| {
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
            }
            StatusCode::GONE => {
                let stale_devices = response.json().await.map_err(|e| {
                    log::error!("Failed to decode HTTP 410 response: {}", e);
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::GONE.as_u16(),
                    }
                })?;
                Err(ServiceError::StaleDevices(stale_devices))
            }
            // XXX: fill in rest from PushServiceSocket
            code => {
                let contents = response.body().await;
                log::trace!("Unhandled response with body: {:?}", contents);
                Err(ServiceError::UnhandledResponseCode {
                    http_code: code.as_u16(),
                })
            }
        }
    }
}
