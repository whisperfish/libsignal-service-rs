use std::{collections::HashMap, fmt, io, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    envelope::*,
    groups_v2::GroupDecodingError,
    pre_keys::{
        KyberPreKeyEntity, PreKeyEntity, PreKeyState, SignedPreKeyEntity,
    },
    prelude::ServiceConfiguration,
    profile_cipher::ProfileCipherError,
    proto::{attachment_pointer::AttachmentIdentifier, AttachmentPointer},
    sender::{OutgoingPushMessage, OutgoingPushMessages, SendMessageResponse},
    utils::{serde_base64, serde_optional_base64, serde_phone_number},
    websocket::{tungstenite::TungsteniteWebSocket, SignalWebSocket},
    ParseServiceAddressError, Profile, ServiceAddress,
};

use bytes::{Buf, Bytes};
use chrono::prelude::*;
use derivative::Derivative;
use futures::{FutureExt, StreamExt, TryStreamExt};
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
    IdentityKey, PreKeyBundle, PublicKey, SenderCertificate,
};
use phonenumber::PhoneNumber;
use prost::Message as ProtobufMessage;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tracing::{debug, debug_span, Instrument};
use uuid::Uuid;
use zkgroup::{
    profiles::{ProfileKeyCommitment, ProfileKeyVersion},
    ZkGroupDeserializationFailure,
};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub const DEFAULT_DEVICE_ID: u32 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ServiceIdType {
    /// Account Identity (ACI)
    ///
    /// An account UUID without an associated phone number, probably in the future to a username
    AccountIdentity,
    /// Phone number identity (PNI)
    ///
    /// A UUID associated with a phone number
    PhoneNumberIdentity,
}

impl fmt::Display for ServiceIdType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdType::AccountIdentity => f.write_str("aci"),
            ServiceIdType::PhoneNumberIdentity => f.write_str("pni"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceIds {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    #[serde(default)] // nil when not present (yet)
    pub pni: Uuid,
}

impl ServiceIds {
    pub fn aci(&self) -> libsignal_protocol::Aci {
        libsignal_protocol::Aci::from_uuid_bytes(self.aci.into_bytes())
    }

    pub fn pni(&self) -> libsignal_protocol::Pni {
        libsignal_protocol::Pni::from_uuid_bytes(self.pni.into_bytes())
    }
}

impl fmt::Display for ServiceIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aci={} pni={}", self.aci, self.pni)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    pub device_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: i64,
    pub name: Option<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAttributes {
    #[serde(default, with = "serde_optional_base64")]
    pub signaling_key: Option<Vec<u8>>,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    pub pin: Option<String>,
    pub registration_lock: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    pub capabilities: DeviceCapabilities,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    #[serde(default)]
    pub storage: bool,
    #[serde(default)]
    pub sender_key: bool,
    #[serde(default)]
    pub announcement_group: bool,
    #[serde(default)]
    pub change_number: bool,
    #[serde(default)]
    pub stories: bool,
    #[serde(default)]
    pub gift_badges: bool,
    #[serde(default)]
    pub pni: bool,
    #[serde(default)]
    pub payment_activation: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecaptchaAttributes {
    pub r#type: String,
    pub token: String,
    pub captcha: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
    pub pq_count: u32,
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
pub struct WhoAmIResponse {
    pub uuid: Uuid,
    #[serde(default)] // nil when not present (yet)
    pub pni: Uuid,
    #[serde(with = "serde_phone_number")]
    pub number: PhoneNumber,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSessionMetadataResponse {
    pub id: String,
    #[serde(default)]
    pub next_sms: Option<i32>,
    #[serde(default)]
    pub next_call: Option<i32>,
    #[serde(default)]
    pub next_verification_attempt: Option<i32>,
    pub allowed_to_request_code: bool,
    #[serde(default)]
    pub requested_information: Vec<String>,
    pub verified: bool,
}

impl RegistrationSessionMetadataResponse {
    pub fn push_challenge_required(&self) -> bool {
        // .contains() requires &String ...
        self.requested_information
            .iter()
            .any(|x| x.as_str() == "pushChallenge")
    }

    pub fn captcha_required(&self) -> bool {
        // .contains() requires &String ...
        self.requested_information
            .iter()
            .any(|x| x.as_str() == "captcha")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationLockFailure {
    pub length: Option<u32>,
    pub time_remaining: Option<u64>,
    #[serde(rename = "backup_credentials")]
    pub svr1_credentials: Option<AuthCredentials>,
    pub svr2_credentials: Option<AuthCredentials>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyAccountResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    pub pni: Uuid,
    pub storage_capable: bool,
    #[serde(default)]
    pub number: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationTransport {
    Sms,
    Voice,
}

impl VerificationTransport {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sms => "sms",
            Self::Voice => "voice",
        }
    }
}

#[derive(Clone, Debug)]
pub enum RegistrationMethod<'a> {
    SessionId(&'a str),
    RecoveryPassword(&'a str),
}

impl<'a> RegistrationMethod<'a> {
    pub fn session_id(&'a self) -> Option<&'a str> {
        match self {
            Self::SessionId(x) => Some(x),
            _ => None,
        }
    }

    pub fn recovery_password(&'a self) -> Option<&'a str> {
        match self {
            Self::RecoveryPassword(x) => Some(x),
            _ => None,
        }
    }
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequest {
    pub verification_code: String,
    pub account_attributes: LinkAccountAttributes,
    #[serde(flatten)]
    pub device_activation_request: DeviceActivationRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceActivationRequest {
    pub aci_signed_pre_key: SignedPreKeyEntity,
    pub pni_signed_pre_key: SignedPreKeyEntity,
    pub aci_pq_last_resort_pre_key: KyberPreKeyEntity,
    pub pni_pq_last_resort_pre_key: KyberPreKeyEntity,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAccountAttributes {
    pub fetches_messages: bool,
    pub name: String,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub capabilities: LinkCapabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkCapabilities {
    pub delete_sync: bool,
    pub versioned_expiration_timer: bool,
}

// https://github.com/signalapp/Signal-Desktop/blob/1e57db6aa4786dcddc944349e4894333ac2ffc9e/ts/textsecure/WebAPI.ts#L1287
impl Default for LinkCapabilities {
    fn default() -> Self {
        Self {
            delete_sync: true,
            versioned_expiration_timer: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    pub pni: Uuid,
    pub device_id: u32,
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

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV2UploadAttributes {
    key: String,
    credential: String,
    acl: String,
    algorithm: String,
    date: String,
    policy: String,
    signature: String,
    // This is different from Java's implementation,
    // and I (Ruben) am unsure why they decide to force-parse at upload-time instead of at registration
    // time.
    attachment_id: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("Service request timed out: {reason}")]
    Timeout { reason: String },

    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("Error sending request: {reason}")]
    SendError { reason: String },

    #[error("Error decoding response: {reason}")]
    ResponseError { reason: String },

    #[error("Error decoding JSON response: {reason}")]
    JsonDecodeError { reason: String },
    #[error("Error decoding protobuf frame: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("error encoding or decoding bincode: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("error decoding base64 string: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Authorization failed")]
    Unauthorized,
    #[error("Registration lock is set: {0:?}")]
    Locked(RegistrationLockFailure),
    #[error("Unexpected response: HTTP {http_code}")]
    UnhandledResponseCode { http_code: u16 },

    #[error("Websocket error: {reason}")]
    WsError { reason: String },
    #[error("Websocket closing: {reason}")]
    WsClosing { reason: String },

    #[error("Invalid frame: {reason}")]
    InvalidFrameError { reason: String },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] SignalProtocolError),

    #[error("Proof required: {0:?}")]
    ProofRequiredError(ProofRequired),

    #[error("{0:?}")]
    MismatchedDevicesException(MismatchedDevices),

    #[error("{0:?}")]
    StaleDevices(StaleDevices),

    #[error(transparent)]
    CredentialsCacheError(#[from] crate::groups_v2::CredentialsCacheError),

    #[error("groups v2 (zero-knowledge) error")]
    GroupsV2Error,

    #[error(transparent)]
    GroupsV2DecryptionError(#[from] GroupDecodingError),

    #[error(transparent)]
    ZkGroupDeserializationFailure(#[from] ZkGroupDeserializationFailure),

    #[error("unsupported content")]
    UnsupportedContent,

    #[error(transparent)]
    ParseServiceAddress(#[from] ParseServiceAddressError),

    #[error("Not found.")]
    NotFoundError,

    #[error("invalid device name")]
    InvalidDeviceName,
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

    #[tracing::instrument(skip(self))]
    async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
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
                .into_data_stream()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .into_async_read(),
        ))
    }

    #[tracing::instrument(skip(self, value, file), fields(file = file.as_ref().map(|_| "")))]
    pub async fn post_to_cdn0<'s, C>(
        &mut self,
        path: &str,
        value: &[(&str, &str)],
        file: Option<(&str, &'s mut C)>,
    ) -> Result<(), ServiceError>
    where
        C: io::Read + Send + 's,
    {
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

        debug!("HyperPushService::PUT response: {:?}", response);

        Ok(())
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

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    pub async fn devices(&mut self) -> Result<Vec<DeviceInfo>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct DeviceInfoList {
            devices: Vec<DeviceInfo>,
        }

        let devices: DeviceInfoList = self
            .get_json(
                Endpoint::Service,
                "/v1/devices/",
                &[],
                HttpAuthOverride::NoOverride,
            )
            .await?;

        Ok(devices.devices)
    }

    pub async fn unlink_device(&mut self, id: i64) -> Result<(), ServiceError> {
        self.delete_json(Endpoint::Service, &format!("/v1/devices/{}", id), &[])
            .await
    }

    pub async fn get_pre_key_status(
        &mut self,
        service_id_type: ServiceIdType,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.get_json(
            Endpoint::Service,
            &format!("/v2/keys?identity={}", service_id_type),
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    pub async fn register_pre_keys(
        &mut self,
        service_id_type: ServiceIdType,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        match self
            .put_json(
                Endpoint::Service,
                &format!("/v2/keys?identity={}", service_id_type),
                &[],
                HttpAuthOverride::NoOverride,
                pre_key_state,
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        }
    }

    pub async fn get_attachment_by_id(
        &mut self,
        id: &str,
        cdn_id: u32,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("attachments/{}", id);
        self.get_from_cdn(cdn_id, &path).await
    }

    pub async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        match ptr.attachment_identifier.as_ref().unwrap() {
            AttachmentIdentifier::CdnId(id) => {
                // cdn_number did not exist for this part of the protocol.
                // cdn_number(), however, returns 0 when the field does not
                // exist.
                self.get_attachment_by_id(&format!("{}", id), ptr.cdn_number())
                    .await
            },
            AttachmentIdentifier::CdnKey(key) => {
                self.get_attachment_by_id(key, ptr.cdn_number()).await
            },
        }
    }

    pub async fn get_sticker_pack_manifest(
        &mut self,
        id: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("/stickers/{}/manifest.proto", id);
        self.get_from_cdn(0, &path).await
    }

    pub async fn get_sticker(
        &mut self,
        pack_id: &str,
        sticker_id: u32,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("/stickers/{}/full/{}", pack_id, sticker_id);
        self.get_from_cdn(0, &path).await
    }

    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.destination);
        self.put_json(
            Endpoint::Service,
            &path,
            &[],
            HttpAuthOverride::NoOverride,
            messages,
        )
        .await
    }

    /// Request AttachmentV2UploadAttributes
    ///
    /// Equivalent with getAttachmentV2UploadAttributes
    async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v2/attachments/form/upload",
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    /// Upload attachment to CDN
    ///
    /// Returns attachment ID and the attachment digest
    pub async fn upload_attachment<'s, C>(
        &mut self,
        attrs: &AttachmentV2UploadAttributes,
        content: &'s mut C,
    ) -> Result<(u64, Vec<u8>), ServiceError>
    where
        C: std::io::Read + Send + 's,
    {
        let values = [
            ("acl", &attrs.acl as &str),
            ("key", &attrs.key),
            ("policy", &attrs.policy),
            ("Content-Type", "application/octet-stream"),
            ("x-amz-algorithm", &attrs.algorithm),
            ("x-amz-credential", &attrs.credential),
            ("x-amz-date", &attrs.date),
            ("x-amz-signature", &attrs.signature),
        ];

        let mut digester = crate::digeststream::DigestingReader::new(content);

        self.post_to_cdn0(
            "attachments/",
            &values,
            Some(("file", &mut digester)),
        )
        .await?;
        Ok((attrs.attachment_id, digester.finalize()))
    }

    pub async fn get_messages(
        &mut self,
        allow_stories: bool,
    ) -> Result<Vec<EnvelopeEntity>, ServiceError> {
        let entity_list: EnvelopeEntityList = self
            .get_json(
                Endpoint::Service,
                "/v1/messages/",
                &[(
                    "X-Signal-Receive-Stories",
                    if allow_stories { "true" } else { "false" },
                )],
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(entity_list.messages)
    }

    /// Method used to check our own UUID
    pub async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v1/accounts/whoami",
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    pub async fn retrieve_profile_by_id(
        &mut self,
        address: ServiceAddress,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let endpoint = if let Some(key) = profile_key {
            let version = bincode::serialize(&key.get_profile_key_version(
                address.aci().expect("profile by ACI ProtocolAddress"),
            ))?;
            let version = std::str::from_utf8(&version)
                .expect("hex encoded profile key version");
            format!("/v1/profile/{}/{}", address.uuid, version)
        } else {
            format!("/v1/profile/{}", address.uuid)
        };
        // TODO: set locale to en_US
        self.get_json(
            Endpoint::Service,
            &endpoint,
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    pub async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.get_from_cdn(0, path).await
    }

    pub async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.get_from_cdn(0, path).await
    }

    pub async fn get_pre_key(
        &mut self,
        destination: &ServiceAddress,
        device_id: u32,
    ) -> Result<PreKeyBundle, ServiceError> {
        let path =
            format!("/v2/keys/{}/{}?pq=true", destination.uuid, device_id);

        let mut pre_key_response: PreKeyResponse = self
            .get_json(
                Endpoint::Service,
                &path,
                &[],
                HttpAuthOverride::NoOverride,
            )
            .await?;
        assert!(!pre_key_response.devices.is_empty());

        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        let device = pre_key_response.devices.remove(0);
        Ok(device.into_bundle(identity)?)
    }

    pub(crate) async fn get_pre_keys(
        &mut self,
        destination: &ServiceAddress,
        device_id: u32,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let path = if device_id == 1 {
            format!("/v2/keys/{}/*?pq=true", destination.uuid)
        } else {
            format!("/v2/keys/{}/{}?pq=true", destination.uuid, device_id)
        };
        let pre_key_response: PreKeyResponse = self
            .get_json(
                Endpoint::Service,
                &path,
                &[],
                HttpAuthOverride::NoOverride,
            )
            .await?;
        let mut pre_keys = vec![];
        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        for device in pre_key_response.devices {
            pre_keys.push(device.into_bundle(identity)?);
        }
        Ok(pre_keys)
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

    async fn get_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .get_json(
                Endpoint::Service,
                "/v1/certificate/delivery",
                &[],
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    async fn get_uuid_only_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .get_json(
                Endpoint::Service,
                "/v1/certificate/delivery?includeE164=false",
                &[],
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    pub async fn link_device(
        &mut self,
        link_request: &LinkRequest,
        http_auth: HttpAuth,
    ) -> Result<LinkResponse, ServiceError> {
        self.put_json(
            Endpoint::Service,
            "/v1/devices/link",
            &[],
            HttpAuthOverride::Identified(http_auth),
            link_request,
        )
        .await
    }

    pub async fn set_account_attributes(
        &mut self,
        attributes: AccountAttributes,
    ) -> Result<(), ServiceError> {
        assert!(
            attributes.pin.is_none() || attributes.registration_lock.is_none(),
            "only one of PIN and registration lock can be set."
        );

        match self
            .put_json(
                Endpoint::Service,
                "/v1/accounts/attributes/",
                &[],
                HttpAuthOverride::NoOverride,
                attributes,
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        }
    }

    /// Writes a profile and returns the avatar URL, if one was provided.
    ///
    /// The name, about and emoji fields are encrypted with an [`ProfileCipher`][struct@crate::profile_cipher::ProfileCipher].
    /// See [`AccountManager`][struct@crate::AccountManager] for a convenience method.
    ///
    /// Java equivalent: `writeProfile`
    pub async fn write_profile<'s, C, S>(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        commitment: &ProfileKeyCommitment,
        avatar: AvatarWrite<&mut C>,
    ) -> Result<Option<String>, ServiceError>
    where
        C: std::io::Read + Send + 's,
        S: AsRef<str>,
    {
        #[derive(Debug, Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignalServiceProfileWrite<'s> {
            /// Hex-encoded
            version: &'s str,
            #[serde(with = "serde_base64")]
            name: &'s [u8],
            #[serde(with = "serde_base64")]
            about: &'s [u8],
            #[serde(with = "serde_base64")]
            about_emoji: &'s [u8],
            avatar: bool,
            same_avatar: bool,
            #[serde(with = "serde_base64")]
            commitment: &'s [u8],
        }

        // Bincode is transparent and will return a hex-encoded string.
        let version = bincode::serialize(version)?;
        let version = std::str::from_utf8(&version)
            .expect("profile_key_version is hex encoded string");
        let commitment = bincode::serialize(commitment)?;

        let command = SignalServiceProfileWrite {
            version,
            name,
            about,
            about_emoji: emoji,
            avatar: !matches!(avatar, AvatarWrite::NoAvatar),
            same_avatar: matches!(avatar, AvatarWrite::RetainAvatar),
            commitment: &commitment,
        };

        // XXX this should  be a struct; cfr ProfileAvatarUploadAttributes
        let response: Result<String, _> = self
            .put_json(
                Endpoint::Service,
                "/v1/profile",
                &[],
                HttpAuthOverride::NoOverride,
                command,
            )
            .await;
        match (response, avatar) {
            (Ok(_url), AvatarWrite::NewAvatar(_avatar)) => {
                // FIXME
                unreachable!("Uploading avatar unimplemented");
            },
            // FIXME cleanup when #54883 is stable and MSRV:
            // or-patterns syntax is experimental
            // see issue #54883 <https://github.com/rust-lang/rust/issues/54883> for more information
            (
                Err(ServiceError::JsonDecodeError { .. }),
                AvatarWrite::RetainAvatar,
            )
            | (
                Err(ServiceError::JsonDecodeError { .. }),
                AvatarWrite::NoAvatar,
            ) => {
                // OWS sends an empty string when there's no attachment
                Ok(None)
            },
            (Err(e), _) => Err(e),
            (Ok(_resp), AvatarWrite::RetainAvatar)
            | (Ok(_resp), AvatarWrite::NoAvatar) => {
                tracing::warn!(
                    "No avatar supplied but got avatar upload URL. Ignoring"
                );
                Ok(None)
            },
        }
    }

    // Equivalent of Java's
    // RegistrationSessionMetadataResponse createVerificationSession(@Nullable String pushToken, @Nullable String mcc, @Nullable String mnc)
    async fn create_verification_session<'a>(
        &mut self,
        number: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct VerificationSessionMetadataRequestBody<'a> {
            number: &'a str,
            push_token: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        let req = VerificationSessionMetadataRequestBody {
            number,
            push_token_type: push_token.as_ref().map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
        };

        let res: RegistrationSessionMetadataResponse = self
            .post_json(
                Endpoint::Service,
                "/v1/verification/session",
                &[],
                HttpAuthOverride::Unidentified,
                req,
            )
            .await?;
        Ok(res)
    }

    // Equivalent of Java's
    // RegistrationSessionMetadataResponse patchVerificationSession(String sessionId, @Nullable String pushToken, @Nullable String mcc, @Nullable String mnc, @Nullable String captchaToken, @Nullable String pushChallengeToken)
    async fn patch_verification_session<'a>(
        &mut self,
        session_id: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
        captcha: Option<&'a str>,
        push_challenge: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct UpdateVerificationSessionRequestBody<'a> {
            captcha: Option<&'a str>,
            push_token: Option<&'a str>,
            push_challenge: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        let req = UpdateVerificationSessionRequestBody {
            captcha,
            push_token_type: push_token.as_ref().map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
            push_challenge,
        };

        let res: RegistrationSessionMetadataResponse = self
            .patch_json(
                Endpoint::Service,
                &format!("/v1/verification/session/{}", session_id),
                &[],
                HttpAuthOverride::Unidentified,
                req,
            )
            .await?;
        Ok(res)
    }

    // Equivalent of Java's
    // RegistrationSessionMetadataResponse requestVerificationCode(String sessionId, Locale locale, boolean androidSmsRetriever, VerificationCodeTransport transport)
    /// Request a verification code.
    ///
    /// Signal requires a client type, and they use these three strings internally:
    /// - "android-2021-03"
    /// - "android"
    /// - "ios"
    /// "android-2021-03" allegedly implies FCM support, whereas the other strings don't.  In
    /// principle, they will consider any string as "unknown", so other strings may work too.
    async fn request_verification_code(
        &mut self,
        session_id: &str,
        client: &str,
        // XXX: We currently don't support this, because we need to set some headers in the
        //      post_json() call
        // locale: Option<String>,
        transport: VerificationTransport,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        let mut req = std::collections::HashMap::new();
        req.insert("transport", transport.as_str());
        req.insert("client", client);

        let res: RegistrationSessionMetadataResponse = self
            .post_json(
                Endpoint::Service,
                &format!("/v1/verification/session/{}/code", session_id),
                &[],
                HttpAuthOverride::Unidentified,
                req,
            )
            .await?;
        Ok(res)
    }

    async fn submit_verification_code(
        &mut self,
        session_id: &str,
        verification_code: &str,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        let mut req = std::collections::HashMap::new();
        req.insert("code", verification_code);

        let res: RegistrationSessionMetadataResponse = self
            .put_json(
                Endpoint::Service,
                &format!("/v1/verification/session/{}/code", session_id),
                &[],
                HttpAuthOverride::Unidentified,
                req,
            )
            .await?;
        Ok(res)
    }

    pub async fn submit_registration_request<'a>(
        &mut self,
        registration_method: RegistrationMethod<'a>,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
        aci_identity_key: &IdentityKey,
        pni_identity_key: &IdentityKey,
        device_activation_request: DeviceActivationRequest,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct RegistrationSessionRequestBody<'a> {
            // Unhandled response 422 with body:
            // {"errors":["deviceActivationRequest.pniSignedPreKey must not be
            // null","deviceActivationRequest.pniPqLastResortPreKey must not be
            // null","everySignedKeyValid must be true","aciIdentityKey must not be
            // null","pniIdentityKey must not be null","deviceActivationRequest.aciSignedPreKey
            // must not be null","deviceActivationRequest.aciPqLastResortPreKey must not be null"]}
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: AccountAttributes,
            skip_device_transfer: bool,
            every_signed_key_valid: bool,
            #[serde(default, with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            #[serde(default, with = "serde_base64")]
            aci_identity_key: Vec<u8>,
            #[serde(flatten)]
            device_activation_request: DeviceActivationRequest,
        }

        let req = RegistrationSessionRequestBody {
            session_id: registration_method.session_id(),
            recovery_password: registration_method.recovery_password(),
            account_attributes,
            skip_device_transfer,
            aci_identity_key: aci_identity_key.serialize().into(),
            pni_identity_key: pni_identity_key.serialize().into(),
            device_activation_request,
            every_signed_key_valid: true,
        };

        let res: VerifyAccountResponse = self
            .post_json(
                Endpoint::Service,
                "/v1/registration",
                &[],
                HttpAuthOverride::NoOverride,
                req,
            )
            .await?;
        Ok(res)
    }

    pub async fn distribute_pni_keys(
        &mut self,
        pni_identity_key: &IdentityKey,
        device_messages: Vec<OutgoingPushMessage>,
        device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
        device_pni_last_resort_kyber_prekeys: HashMap<
            String,
            KyberPreKeyEntity,
        >,
        pni_registration_ids: HashMap<String, u32>,
        signature_valid_on_each_signed_pre_key: bool,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct PniKeyDistributionRequest {
            #[serde(with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            device_messages: Vec<OutgoingPushMessage>,
            device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
            #[serde(rename = "devicePniPqLastResortPrekeys")]
            device_pni_last_resort_kyber_prekeys:
                HashMap<String, KyberPreKeyEntity>,
            pni_registration_ids: HashMap<String, u32>,
            signature_valid_on_each_signed_pre_key: bool,
        }

        let res: VerifyAccountResponse = self
            .put_json(
                Endpoint::Service,
                "/v2/accounts/phone_number_identity_key_distribution",
                &[],
                HttpAuthOverride::NoOverride,
                PniKeyDistributionRequest {
                    pni_identity_key: pni_identity_key.serialize().into(),
                    device_messages,
                    device_pni_signed_prekeys,
                    device_pni_last_resort_kyber_prekeys,
                    pni_registration_ids,
                    signature_valid_on_each_signed_pre_key,
                },
            )
            .await?;
        Ok(res)
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
