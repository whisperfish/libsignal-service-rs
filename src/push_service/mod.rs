use std::time::Duration;

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::{KyberPreKeyEntity, PreKeyEntity, SignedPreKeyEntity},
    prelude::ServiceConfiguration,
    utils::serde_base64,
    websocket::SignalWebSocket,
};

use derivative::Derivative;
use libsignal_protocol::{
    error::SignalProtocolError,
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey,
};
use protobuf::ProtobufResponseExt;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use reqwest_websocket::RequestBuilderExt;
use serde::{Deserialize, Serialize};
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub const DEFAULT_DEVICE_ID: u32 = 1;

mod account;
mod cdn;
mod error;
mod keys;
mod linking;
mod profile;
mod registration;
mod stickers;

pub use account::*;
pub use cdn::*;
pub use error::*;
pub use keys::*;
pub use linking::*;
pub use profile::*;
pub use registration::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(Derivative, Clone, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct HttpAuth {
    pub username: String,
    #[derivative(Debug = "ignore")]
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
struct SenderCertificateJson {
    #[serde(with = "serde_base64")]
    certificate: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponse {
    #[serde(with = "serde_base64")]
    pub identity_key: Vec<u8>,
    pub devices: Vec<PreKeyResponseItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    pub device_id: u32,
    pub registration_id: u32,
    pub signed_pre_key: SignedPreKeyEntity,
    pub pre_key: Option<PreKeyEntity>,
    pub pq_pre_key: Option<KyberPreKeyEntity>,
}

impl PreKeyResponseItem {
    pub(crate) fn into_bundle(
        self,
        identity: IdentityKey,
    ) -> Result<PreKeyBundle, SignalProtocolError> {
        let b = PreKeyBundle::new(
            self.registration_id,
            self.device_id.into(),
            self.pre_key
                .map(|pk| -> Result<_, SignalProtocolError> {
                    Ok((
                        pk.key_id.into(),
                        PublicKey::deserialize(&pk.public_key)?,
                    ))
                })
                .transpose()?,
            // pre_key: Option<(u32, PublicKey)>,
            self.signed_pre_key.key_id.into(),
            PublicKey::deserialize(&self.signed_pre_key.public_key)?,
            self.signed_pre_key.signature,
            identity,
        )?;

        if let Some(pq_pk) = self.pq_pre_key {
            Ok(b.with_kyber_pre_key(
                pq_pk.key_id.into(),
                Key::<Public>::deserialize(&pq_pk.public_key)?,
                pq_pk.signature,
            ))
        } else {
            Ok(b)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    pub missing_devices: Vec<u32>,
    pub extra_devices: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    pub stale_devices: Vec<u32>,
}

#[derive(Clone)]
pub struct PushService {
    cfg: ServiceConfiguration,
    credentials: Option<HttpAuth>,
    client: reqwest::Client,
}

impl PushService {
    pub fn new(
        cfg: impl Into<ServiceConfiguration>,
        credentials: Option<ServiceCredentials>,
        user_agent: impl AsRef<str>,
    ) -> Self {
        let cfg = cfg.into();
        let client = reqwest::ClientBuilder::new()
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    &cfg.certificate_authority.as_bytes(),
                )
                .unwrap(),
            )
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(65))
            .user_agent(user_agent.as_ref())
            .build()
            .unwrap();

        Self {
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
        }
    }

    #[tracing::instrument(skip(self, path), fields(path = %path.as_ref()))]
    pub fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        path: impl AsRef<str>,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder, ServiceError> {
        let url = self.cfg.base_url(endpoint).join(path.as_ref())?;
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
}

#[async_trait::async_trait]
pub(crate) trait ReqwestExt
where
    Self: Sized,
{
    async fn send_to_signal(self) -> Result<Response, ServiceError>;
}

#[async_trait::async_trait]
impl ReqwestExt for RequestBuilder {
    async fn send_to_signal(self) -> Result<Response, ServiceError> {
        let response = self.send().await?;
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
                    response.json().await.map_err(|error| {
                        tracing::error!(
                            %error,
                            "failed to decode HTTP 409 status"
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
                let stale_devices = response.json().await.map_err(|error| {
                    tracing::error!(%error, "failed to decode HTTP 410 status");
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::GONE.as_u16(),
                    }
                })?;
                Err(ServiceError::StaleDevices(stale_devices))
            },
            StatusCode::LOCKED => {
                let locked = response.json().await.map_err(|error| {
                    tracing::error!(%error, "failed to decode HTTP 423 status");
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::LOCKED.as_u16(),
                    }
                })?;
                Err(ServiceError::Locked(locked))
            },
            StatusCode::PRECONDITION_REQUIRED => {
                let proof_required =
                    response.json().await.map_err(|error| {
                        tracing::error!(
                            %error,
                            "failed to decode HTTP 428 status"
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
                let response_text = response.text().await?;
                tracing::trace!(status_code =% code, body = response_text, "unhandled HTTP response");
                Err(ServiceError::UnhandledResponseCode {
                    http_code: code.as_u16(),
                })
            },
        }
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
        /// Sets the `Content-Type` header to `application/protobuf`
        #[allow(dead_code)]
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError>;
    }

    #[async_trait::async_trait]
    pub(crate) trait ProtobufResponseExt {
        /// Get the response body decoded from Protobuf
        async fn protobuf<T: prost::Message + Default>(
            self,
        ) -> Result<T, ServiceError>;
    }

    impl ProtobufRequestBuilderExt for RequestBuilder {
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError> {
            let mut buf = Vec::new();
            value.encode(&mut buf)?;
            let this =
                self.header(header::CONTENT_TYPE, "application/protobuf");
            Ok(this.body(buf))
        }
    }

    #[async_trait]
    impl ProtobufResponseExt for Response {
        async fn protobuf<T: Message + Default>(
            self,
        ) -> Result<T, ServiceError> {
            let body = self.bytes().await?;
            let decoded = T::decode(body)?;
            Ok(decoded)
        }
    }
}

impl PushService {
    pub async fn ws(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket, ServiceError> {
        let span = debug_span!("websocket");

        let endpoint = self.cfg.base_url(Endpoint::Service);
        let mut url = endpoint.join(path).expect("valid url");
        url.set_scheme("wss").expect("valid https base url");

        if let Some(credentials) = credentials {
            url.query_pairs_mut()
                .append_pair("login", &credentials.login())
                .append_pair(
                    "password",
                    credentials.password.as_ref().expect("a password"),
                );
        }

        let mut builder = self.client.get(url);
        for (key, value) in additional_headers {
            builder = builder.header(*key, *value);
        }

        let ws = builder
            .upgrade()
            .send()
            .await?
            .into_websocket()
            .instrument(span.clone())
            .await?;

        let (ws, task) =
            SignalWebSocket::from_socket(ws, keepalive_path.to_owned());
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
            Endpoint::Storage,
            "/v1/groups/",
            HttpAuthOverride::Identified(credentials),
        )?
        .send()
        .await?
        .protobuf()
        .await
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::SignalServers;
    use bytes::{Buf, Bytes};

    #[test]
    fn create_clients() {
        let configs = &[SignalServers::Staging, SignalServers::Production];

        for cfg in configs {
            let _ = super::PushService::new(
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
