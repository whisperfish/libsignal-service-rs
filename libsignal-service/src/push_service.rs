use std::{fmt, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    envelope::*,
    groups_v2::GroupDecodingError,
    pre_keys::{
        KyberPreKeyEntity, PreKeyEntity, PreKeyState, SignedPreKeyEntity,
    },
    profile_cipher::ProfileCipherError,
    proto::{attachment_pointer::AttachmentIdentifier, AttachmentPointer},
    sender::{OutgoingPushMessages, SendMessageResponse},
    utils::{serde_base64, serde_optional_base64, serde_phone_number},
    websocket::SignalWebSocket,
    MaybeSend, ParseServiceAddressError, Profile, ServiceAddress,
};

use chrono::prelude::*;
use derivative::Derivative;
use libsignal_protocol::{
    error::SignalProtocolError,
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey, SenderCertificate,
};
use phonenumber::PhoneNumber;
use prost::Message as ProtobufMessage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::profiles::{ProfileKeyCommitment, ProfileKeyVersion};

/**
Since we can't use format!() with constants, the URLs here are just for reference purposes
pub const REGISTER_GCM_PATH: &str = "/v1/accounts/gcm/";
pub const TURN_SERVER_INFO: &str = "/v1/accounts/turn";
pub const SET_ACCOUNT_ATTRIBUTES: &str = "/v1/accounts/attributes/";
pub const PIN_PATH: &str = "/v1/accounts/pin/";
pub const REQUEST_PUSH_CHALLENGE: &str = "/v1/accounts/fcm/preauth/%s/%s";
pub const WHO_AM_I: &str = "/v1/accounts/whoami";

pub const PREKEY_PATH: &str = "/v2/keys/%s";
pub const PREKEY_DEVICE_PATH: &str = "/v2/keys/%s/%s";
pub const SIGNED_PREKEY_PATH: &str = "/v2/keys/signed";

pub const PROVISIONING_CODE_PATH: &str = "/v1/devices/provisioning/code";
pub const PROVISIONING_MESSAGE_PATH: &str = "/v1/provisioning/%s";

pub const DIRECTORY_TOKENS_PATH: &str = "/v1/directory/tokens";
pub const DIRECTORY_VERIFY_PATH: &str = "/v1/directory/%s";
pub const DIRECTORY_AUTH_PATH: &str = "/v1/directory/auth";
pub const DIRECTORY_FEEDBACK_PATH: &str = "/v1/directory/feedback-v3/%s";
pub const SENDER_ACK_MESSAGE_PATH: &str = "/v1/messages/%s/%d";
pub const UUID_ACK_MESSAGE_PATH: &str = "/v1/messages/uuid/%s";
pub const ATTACHMENT_PATH: &str = "/v2/attachments/form/upload";

pub const PROFILE_PATH: &str = "/v1/profile/";

pub const SENDER_CERTIFICATE_LEGACY_PATH: &str = "/v1/certificate/delivery";
pub const SENDER_CERTIFICATE_PATH: &str =
    "/v1/certificate/delivery?includeUuid=true";

pub const VERIFICATION_SESSION_PATH: &str = "/v1/verification/session";
pub const VERIFICATION_CODE_PATH: &str    = "/v1/verification/session/%s/code";

pub const REGISTRATION_PATH: &str    = "/v1/registration";

pub const ATTACHMENT_DOWNLOAD_PATH: &str = "attachments/%d";

pub const STICKER_MANIFEST_PATH: &str = "stickers/%s/manifest.proto";
pub const STICKER_PATH: &str = "stickers/%s/full/%d";
**/

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub const DEFAULT_DEVICE_ID: u32 = 1;

#[derive(Debug, Clone, Copy)]
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
    pub announcement_group: bool,
    #[serde(rename(serialize = "gv2-3"), alias = "gv2-3", default)]
    pub gv2: bool,
    #[serde(default)]
    pub storage: bool,
    #[serde(rename = "gv1-migration", default)]
    pub gv1_migration: bool,
    #[serde(default)]
    pub sender_key: bool,
    #[serde(default)]
    pub change_number: bool,
    #[serde(default)]
    pub stories: bool,
    #[serde(default)]
    pub gift_badges: bool,
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

#[derive(Derivative, Clone)]
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
pub struct VerifyAccountResponse {
    pub uuid: Uuid,
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

    #[error("unsupported content")]
    UnsupportedContent,

    #[error(transparent)]
    ParseServiceAddress(#[from] ParseServiceAddressError),

    #[error("Not found.")]
    NotFoundError,
}

pub(crate) const NO_ADDITIONAL_HEADERS: &[(&str, &str)] = &[];

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
pub trait PushService: MaybeSend {
    type ByteStream: futures::io::AsyncRead + Unpin;

    async fn get_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn delete_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

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
        S: MaybeSend + Serialize;

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
        S: MaybeSend + Serialize;

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
        S: MaybeSend + Serialize;

    async fn get_protobuf<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        T: Default + ProtobufMessage;

    async fn put_protobuf<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        additional_headers: &[(&str, &str)],
        value: S,
    ) -> Result<D, ServiceError>
    where
        D: Default + ProtobufMessage,
        S: Sized + ProtobufMessage;

    /// Downloads larger files in streaming fashion, e.g. attachments.
    async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<Self::ByteStream, ServiceError>;

    /// Upload larger file to CDN0 in legacy fashion, e.g. for attachments.
    ///
    /// Implementations are allowed to *panic* when the Read instance throws an IO-Error
    async fn post_to_cdn0<'s, C: std::io::Read + Send + 's>(
        &mut self,
        path: &str,
        value: &[(&str, &str)],
        file: Option<(&str, &'s mut C)>,
    ) -> Result<(), ServiceError>;

    async fn ws(
        &mut self,
        path: &str,
        credentials: Option<ServiceCredentials>,
        keep_alive: bool,
    ) -> Result<SignalWebSocket, ServiceError>;

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    async fn devices(&mut self) -> Result<Vec<DeviceInfo>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct DeviceInfoList {
            devices: Vec<DeviceInfo>,
        }

        let devices: DeviceInfoList = self
            .get_json(
                Endpoint::Service,
                "/v1/devices/",
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
            )
            .await?;

        Ok(devices.devices)
    }

    async fn unlink_device(&mut self, id: i64) -> Result<(), ServiceError> {
        self.delete_json(
            Endpoint::Service,
            &format!("/v1/devices/{}", id),
            NO_ADDITIONAL_HEADERS,
        )
        .await
    }

    async fn get_pre_key_status(
        &mut self,
        service_id_type: ServiceIdType,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.get_json(
            Endpoint::Service,
            &format!("/v2/keys?identity={}", service_id_type),
            NO_ADDITIONAL_HEADERS,
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn register_pre_keys(
        &mut self,
        service_id_type: ServiceIdType,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        match self
            .put_json(
                Endpoint::Service,
                &format!("/v2/keys?identity={}", service_id_type),
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
                pre_key_state,
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        }
    }

    async fn get_attachment_by_id(
        &mut self,
        id: &str,
        cdn_id: u32,
    ) -> Result<Self::ByteStream, ServiceError> {
        let path = format!("attachments/{}", id);
        self.get_from_cdn(cdn_id, &path).await
    }

    async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<Self::ByteStream, ServiceError> {
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

    async fn get_sticker_pack_manifest(
        &mut self,
        id: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        let path = format!("/stickers/{}/manifest.proto", id);
        self.get_from_cdn(0, &path).await
    }

    async fn get_sticker(
        &mut self,
        pack_id: &str,
        sticker_id: u32,
    ) -> Result<Self::ByteStream, ServiceError> {
        let path = format!("/stickers/{}/full/{}", pack_id, sticker_id);
        self.get_from_cdn(0, &path).await
    }

    async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.recipient.uuid);
        self.put_json(
            Endpoint::Service,
            &path,
            NO_ADDITIONAL_HEADERS,
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
            NO_ADDITIONAL_HEADERS,
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    /// Upload attachment to CDN
    ///
    /// Returns attachment ID and the attachment digest
    async fn upload_attachment<'s, C: std::io::Read + Send + 's>(
        &mut self,
        attrs: &AttachmentV2UploadAttributes,
        content: &'s mut C,
    ) -> Result<(u64, Vec<u8>), ServiceError> {
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

    async fn get_messages(
        &mut self,
    ) -> Result<Vec<EnvelopeEntity>, ServiceError> {
        let entity_list: EnvelopeEntityList = self
            .get_json(
                Endpoint::Service,
                "/v1/messages/",
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(entity_list.messages)
    }

    /// Method used to check our own UUID
    async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v1/accounts/whoami",
            NO_ADDITIONAL_HEADERS,
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn retrieve_profile_by_id(
        &mut self,
        address: ServiceAddress,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let endpoint = if let Some(key) = profile_key {
            let uid_bytes = address.uuid.as_bytes();
            let version =
                bincode::serialize(&key.get_profile_key_version(*uid_bytes))?;
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
            NO_ADDITIONAL_HEADERS,
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        self.get_from_cdn(0, path).await
    }

    async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        self.get_from_cdn(0, path).await
    }

    async fn get_pre_key(
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
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
            )
            .await?;
        assert!(!pre_key_response.devices.is_empty());

        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        let device = pre_key_response.devices.remove(0);
        Ok(device.into_bundle(identity)?)
    }

    async fn get_pre_keys(
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
                NO_ADDITIONAL_HEADERS,
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

    async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.get_protobuf(
            Endpoint::Storage,
            "/v1/groups/",
            NO_ADDITIONAL_HEADERS,
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
                NO_ADDITIONAL_HEADERS,
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
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    async fn set_account_attributes(
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
                NO_ADDITIONAL_HEADERS,
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
    async fn write_profile<'s, C: std::io::Read + Send + 's, S: AsRef<str>>(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        commitment: &ProfileKeyCommitment,
        avatar: AvatarWrite<&mut C>,
    ) -> Result<Option<String>, ServiceError> {
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
                NO_ADDITIONAL_HEADERS,
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
                log::warn!(
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
                NO_ADDITIONAL_HEADERS,
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
                NO_ADDITIONAL_HEADERS,
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
                NO_ADDITIONAL_HEADERS,
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
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::Unidentified,
                req,
            )
            .await?;
        Ok(res)
    }

    async fn submit_registration_request<'a>(
        &mut self,
        registration_method: RegistrationMethod<'a>,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct RegistrationSessionRequestBody<'a> {
            // TODO: This is an "old" version of the request. The new one includes atomic
            // registration of prekeys and identities, but I'm to lazy to implement them today.
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: AccountAttributes,
            skip_device_transfer: bool,
        }

        let req = RegistrationSessionRequestBody {
            session_id: registration_method.session_id(),
            recovery_password: registration_method.recovery_password(),
            account_attributes,
            skip_device_transfer,
        };

        let res: VerifyAccountResponse = self
            .post_json(
                Endpoint::Service,
                "/v1/registration",
                NO_ADDITIONAL_HEADERS,
                HttpAuthOverride::NoOverride,
                req,
            )
            .await?;
        Ok(res)
    }
}
