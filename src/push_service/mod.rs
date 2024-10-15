use std::{io, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::{KyberPreKeyEntity, PreKeyEntity, SignedPreKeyEntity},
    prelude::ServiceConfiguration,
    profile_cipher::ProfileCipherError,
    utils::{serde_base64, serde_optional_base64},
    websocket::{tungstenite::TungsteniteWebSocket, SignalWebSocket},
    Profile,
};

use bytes::{Buf, Bytes};
use derivative::Derivative;
use headers::{Authorization, HeaderMapExt};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT},
    Method, Request, Response, StatusCode,
};
use hyper_rustls::HttpsConnector;
use hyper_timeout::TimeoutConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use libsignal_protocol::{
    error::SignalProtocolError,
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey,
};
use prost::Message as ProtobufMessage;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub const DEFAULT_DEVICE_ID: u32 = 1;

mod account;
mod captcha;
mod cdn;
mod error;
mod keys;
mod linking;
mod profile;
mod registration;
mod stickers;

pub use account::*;
pub use captcha::*;
pub use cdn::*;
pub use error::*;
pub use keys::*;
pub use linking::*;
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

/// This type is used in registration lock handling.
/// It's identical with HttpAuth, but used to avoid type confusion.
#[derive(Derivative, Clone, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct AuthCredentials {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfile {
    #[serde(default, with = "serde_optional_base64")]
    pub identity_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub name: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about_emoji: Option<Vec<u8>>,

    // TODO: not sure whether this is via optional_base64
    // #[serde(default, with = "serde_optional_base64")]
    // pub payment_address: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub unidentified_access: Option<String>,

    #[serde(default)]
    pub unrestricted_unidentified_access: bool,

    pub capabilities: DeviceCapabilities,
}

impl SignalServiceProfile {
    pub fn decrypt(
        &self,
        profile_cipher: crate::profile_cipher::ProfileCipher,
    ) -> Result<Profile, ProfileCipherError> {
        // Profile decryption
        let name = self
            .name
            .as_ref()
            .map(|data| profile_cipher.decrypt_name(data))
            .transpose()?
            .flatten();
        let about = self
            .about
            .as_ref()
            .map(|data| profile_cipher.decrypt_about(data))
            .transpose()?;
        let about_emoji = self
            .about_emoji
            .as_ref()
            .map(|data| profile_cipher.decrypt_emoji(data))
            .transpose()?;

        Ok(Profile {
            name,
            about,
            about_emoji,
            avatar: self.avatar.clone(),
        })
    }
}

#[derive(Debug)]
struct RequestBody {
    contents: Vec<u8>,
    content_type: String,
}

#[derive(Clone)]
pub struct PushService {
    cfg: ServiceConfiguration,
    user_agent: String,
    credentials: Option<HttpAuth>,
    client:
        Client<TimeoutConnector<HttpsConnector<HttpConnector>>, Full<Bytes>>,
}

impl PushService {
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

        let client: Client<_, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build(timeout_connector);

        Self {
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
            user_agent,
        }
    }

    fn tls_config(cfg: &ServiceConfiguration) -> rustls::ClientConfig {
        let mut cert_bytes = io::Cursor::new(&cfg.certificate_authority);
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
    ) -> Result<Response<Incoming>, ServiceError> {
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
                .body(Full::new(Bytes::from(contents)))
                .unwrap()
        } else {
            builder.body(Full::default()).unwrap()
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
            StatusCode::LOCKED => {
                let locked = Self::json(&mut response).await.map_err(|e| {
                    tracing::error!(
                        ?response,
                        "Failed to decode HTTP 423 response: {}",
                        e
                    );
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::LOCKED.as_u16(),
                    }
                })?;
                Err(ServiceError::Locked(locked))
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

    async fn body(
        response: &mut Response<Incoming>,
    ) -> Result<impl Buf, ServiceError> {
        Ok(response
            .collect()
            .await
            .map_err(|e| ServiceError::ResponseError {
                reason: format!("failed to aggregate HTTP response body: {e}"),
            })?
            .aggregate())
    }

    #[tracing::instrument(skip(response), fields(status = %response.status()))]
    async fn json<T>(
        response: &mut Response<Incoming>,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let body = Self::body(response).await?;

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
        response: &mut Response<Incoming>,
    ) -> Result<M, ServiceError>
    where
        M: ProtobufMessage + Default,
    {
        let body = Self::body(response).await?;
        M::decode(body).map_err(ServiceError::ProtobufDecodeError)
    }

    #[tracing::instrument(skip(response), fields(status = %response.status()))]
    async fn text(
        response: &mut Response<Incoming>,
    ) -> Result<String, ServiceError> {
        let body = Self::body(response).await?;
        io::read_to_string(body.reader()).map_err(|e| {
            ServiceError::ResponseError {
                reason: format!("failed to read HTTP response body: {e}"),
            }
        })
    }
}

impl PushService {
    #[tracing::instrument(skip(self))]
    pub(crate) async fn get_json<T>(
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
    pub async fn put_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Send + Serialize,
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
        S: Send + Serialize,
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
        S: Send + Serialize,
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
        T: Default + ProtobufMessage,
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
        D: Default + ProtobufMessage,
        S: Sized + ProtobufMessage,
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

    pub async fn ws(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket, ServiceError> {
        let span = debug_span!("websocket");
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
        tokio::task::spawn(task);
        Ok(ws)
    }

    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.get_protobuf(
            Endpoint::Storage,
            "/v1/groups/",
            &[],
            HttpAuthOverride::Identified(credentials),
        )
        .await
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
