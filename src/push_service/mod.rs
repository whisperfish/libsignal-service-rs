use std::{sync::LazyLock, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials, SignalServers},
    prelude::ServiceConfiguration,
    utils::serde_device_id_vec,
    websocket::{SignalWebSocket, WebSocketType},
};

use libsignal_core::DeviceId;
use protobuf::ProtobufResponseExt;
use reqwest::{Method, RequestBuilder};
use reqwest_websocket::Upgrade;
use serde::{Deserialize, Serialize};
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub static DEFAULT_DEVICE_ID: LazyLock<libsignal_core::DeviceId> =
    LazyLock::new(|| libsignal_core::DeviceId::try_from(1).unwrap());

mod account;
mod cdn;
mod error;
pub mod linking;
pub(crate) mod response;

pub use account::*;
pub use cdn::*;
pub use error::*;
pub(crate) use response::SignalServiceResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuth {
    pub username: String,
    #[debug(ignore)]
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum HttpAuthOverride {
    NoOverride,
    Unidentified,
    Identified(HttpAuth),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AvatarWrite<C> {
    NewAvatar(C),
    RetainAvatar,
    NoAvatar,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    #[serde(with = "serde_device_id_vec")]
    pub missing_devices: Vec<DeviceId>,
    #[serde(with = "serde_device_id_vec")]
    pub extra_devices: Vec<DeviceId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    #[serde(with = "serde_device_id_vec")]
    pub stale_devices: Vec<DeviceId>,
}

#[derive(Clone)]
pub struct PushService {
    pub(crate) servers: SignalServers,
    cfg: ServiceConfiguration,
    credentials: Option<HttpAuth>,
    client: reqwest::Client,
}

/// How long an idle connection stays in the pool: shorter than servers keep one (Jetty, which
/// Signal's storage service runs on, closes one idle for 30 s).
const POOL_IDLE: Duration = Duration::from_secs(20);

/// The client, but for the servers' certificate authority and the user agent.
///
/// A server can close an idle connection just as a request goes out on it: the request then
/// fails, "connection closed before message completed", though the server never saw it. Idle
/// connections are dropped before servers drop them, and a GET that meets one closing anyway
/// is sent once more, as OkHttp does for Signal's apps. Other requests may have taken effect, so
/// they aren't.
fn client_builder() -> reqwest::ClientBuilder {
    // Use the ring provider except if the application already installed one.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(10))
        // Not a total timeout: attachments take as long as they take to transfer.
        .read_timeout(Duration::from_secs(65))
        .http1_only()
        .pool_idle_timeout(POOL_IDLE)
        .retry(
            reqwest::retry::for_host(AnyHost)
                .max_retries_per_request(1)
                .classify_fn(|req_rep| {
                    let closed = req_rep.error().is_some_and(closed_under_request);
                    if closed && req_rep.method() == Method::GET {
                        req_rep.retryable()
                    } else {
                        req_rep.success()
                    }
                }),
        )
}

/// Every host the client is sent to: all of them are Signal's.
struct AnyHost;

impl PartialEq<&str> for AnyHost {
    fn eq(&self, _: &&str) -> bool {
        true
    }
}

/// Whether `error` is a connection closing under a request, before its response.
fn closed_under_request(error: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(error), |error| error.source()).any(|error| {
        error
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_incomplete_message)
    })
}

impl PushService {
    pub fn new(
        env: SignalServers,
        credentials: Option<ServiceCredentials>,
        user_agent: impl AsRef<str>,
    ) -> Self {
        let cfg: ServiceConfiguration = env.into();

        let client = client_builder()
            .tls_certs_only([reqwest::Certificate::from_pem(
                cfg.certificate_authority.as_bytes(),
            )
            .unwrap()])
            .user_agent(user_agent.as_ref())
            .build()
            .unwrap();

        Self {
            servers: env,
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
        }
    }

    #[tracing::instrument(skip(self), fields(endpoint = %endpoint))]
    pub fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder, ServiceError> {
        let url = endpoint.into_url(&self.cfg)?;
        let mut builder = self.client.request(method, url);

        builder = match auth_override {
            HttpAuthOverride::NoOverride => {
                if let Some(HttpAuth { username, password }) =
                    self.credentials.as_ref()
                {
                    builder.basic_auth(username, Some(password))
                } else {
                    builder
                }
            },
            HttpAuthOverride::Identified(HttpAuth { username, password }) => {
                builder.basic_auth(username, Some(password))
            },
            HttpAuthOverride::Unidentified => builder,
        };

        Ok(builder)
    }

    pub async fn ws<C: WebSocketType>(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket<C>, ServiceError> {
        let span = debug_span!("websocket");

        let mut url = Endpoint::service(path).into_url(&self.cfg)?;
        url.set_scheme("wss").expect("valid https base url");

        let mut builder = self.client.get(url);
        for (key, value) in additional_headers {
            builder = builder.header(*key, *value);
        }

        if let Some(credentials) = credentials {
            builder =
                builder.basic_auth(credentials.login(), credentials.password);
        }

        let ws = builder
            .upgrade()
            .send()
            .await?
            .into_websocket()
            .instrument(span.clone())
            .await?;

        let unidentified_push_service = PushService {
            servers: self.servers,
            cfg: self.cfg.clone(),
            credentials: None,
            client: self.client.clone(),
        };
        let (ws, task) = SignalWebSocket::new(
            ws,
            keepalive_path.to_owned(),
            unidentified_push_service,
        );
        let task = task.instrument(span);
        tokio::task::spawn(task);
        Ok(ws)
    }

    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::storage("/v1/groups/"),
            HttpAuthOverride::Identified(credentials),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .protobuf()
        .await
    }
}

pub(crate) mod protobuf {
    use async_trait::async_trait;
    use prost::{EncodeError, Message};
    use reqwest::{header, RequestBuilder, Response};

    use super::ServiceError;

    pub(crate) trait ProtobufRequestBuilderExt
    where
        Self: Sized,
    {
        /// Set the request payload encoded as protobuf.
        /// Sets the `Content-Type` header to `application/x-protobuf`
        #[allow(dead_code)]
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError>;
    }

    #[async_trait::async_trait]
    pub(crate) trait ProtobufResponseExt {
        /// Get the response body decoded from Protobuf
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: prost::Message + Default;
    }

    impl ProtobufRequestBuilderExt for RequestBuilder {
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError> {
            let mut buf = Vec::new();
            value.encode(&mut buf)?;
            let this =
                self.header(header::CONTENT_TYPE, "application/x-protobuf");
            Ok(this.body(buf))
        }
    }

    #[async_trait]
    impl ProtobufResponseExt for Response {
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: Message + Default,
        {
            let body = self.bytes().await?;
            let decoded = T::decode(body)?;
            Ok(decoded)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::SignalServers;
    use bytes::{Buf, Bytes};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::client_builder;

    #[test]
    fn create_clients() {
        let environments = &[SignalServers::Staging, SignalServers::Production];

        for env in environments {
            let _ =
                super::PushService::new(*env, None, "libsignal-service test");
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

    /// A server that answers the first request on each connection, keeps the connection, and
    /// closes it when the next request arrives: what a server closing an idle connection does to
    /// a request that goes out just then. Returns its URL.
    async fn closing_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    if socket.read(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
                        )
                        .await;
                    // The next request, then closed without an answer.
                    let _ = socket.read(&mut buf).await;
                });
            }
        });
        url
    }

    #[tokio::test]
    async fn a_get_on_a_connection_closing_under_it_is_sent_again() {
        let url = closing_server().await;
        let client = client_builder().build().unwrap();
        client.get(&url).send().await.unwrap();
        let again = client.get(&url).send().await;
        assert!(again.is_ok(), "{again:?}");
    }

    /// The server above fails such a request without the retry, as it is meant to.
    #[tokio::test]
    async fn without_the_retry_the_get_fails() {
        let url = closing_server().await;
        let client = client_builder()
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        client.get(&url).send().await.unwrap();
        let error = client.get(&url).send().await.unwrap_err();
        assert!(super::closed_under_request(&error), "{error:?}");
    }

    #[tokio::test]
    async fn a_post_is_not_sent_again() {
        let url = closing_server().await;
        let client = client_builder().build().unwrap();
        client.get(&url).send().await.unwrap();
        let error = client.post(&url).body("x").send().await.unwrap_err();
        assert!(super::closed_under_request(&error), "{error:?}");
    }
}
