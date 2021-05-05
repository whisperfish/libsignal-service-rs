use std::{convert::TryInto, fmt, ops::Deref, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    envelope::*,
    groups_v2::GroupDecryptionError,
    messagepipe::WebSocketService,
    pre_keys::{PreKeyEntity, PreKeyState, SignedPreKeyEntity},
    proto::{attachment_pointer::AttachmentIdentifier, AttachmentPointer},
    sender::{OutgoingPushMessages, SendMessageResponse},
    utils::{serde_base64, serde_optional_base64},
    ServiceAddress,
};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, NewAead,
};
use chrono::prelude::*;
use libsignal_protocol::{
    error::SignalProtocolError, IdentityKey, PreKeyBundle, PublicKey,
};
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

pub const ATTACHMENT_DOWNLOAD_PATH: &str = "attachments/%d";

pub const STICKER_MANIFEST_PATH: &str = "stickers/%s/manifest.proto";
pub const STICKER_PATH: &str = "stickers/%s/full/%d";
**/

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub const DEFAULT_DEVICE_ID: u32 = 1;

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
    #[serde(with = "serde_optional_base64")]
    pub signaling_key: Option<Vec<u8>>,
    pub registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    pub pin: Option<String>,
    pub registration_lock: Option<String>,
    #[serde(with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    pub capabilities: DeviceCapabilities,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    pub uuid: bool,
    #[serde(rename = "gv2-3")]
    pub gv2: bool,
    pub storage: bool,
    #[serde(rename = "gv1-migration")]
    pub gv1_migration: bool,
}

#[derive(Clone)]
pub struct ProfileKey(pub [u8; 32]);

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
}

#[derive(Clone)]
pub struct HttpAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum HttpAuthOverride {
    NoOverride,
    Unidentified,
    Identified(HttpAuth),
}

impl fmt::Debug for HttpAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP auth with username {}", self.username)
    }
}

impl ProfileKey {
    pub fn derive_access_key(&self) -> Vec<u8> {
        let key = GenericArray::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let buf = [0u8; 16];
        cipher.encrypt(nonce, &buf[..]).unwrap()
    }
}

impl Deref for ProfileKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for ProfileKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for ProfileKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(ProfileKey(
            base64::decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?
                .try_into()
                .map_err(|buf: Vec<u8>| {
                    serde::de::Error::invalid_length(
                        buf.len(),
                        &"invalid profile key length",
                    )
                })?,
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponse {
    #[serde(with = "serde_base64")]
    pub identity_key: Vec<u8>,
    pub devices: Vec<PreKeyResponseItem>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WhoAmIResponse {
    pub uuid: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    pub device_id: u32,
    pub registration_id: u32,
    pub signed_pre_key: SignedPreKeyEntity,
    pub pre_key: Option<PreKeyEntity>,
}

impl PreKeyResponseItem {
    fn into_bundle(
        self,
        identity: IdentityKey,
    ) -> Result<PreKeyBundle, SignalProtocolError> {
        PreKeyBundle::new(
            self.registration_id,
            self.device_id,
            self.pre_key
                .map(|pk| -> Result<_, SignalProtocolError> {
                    Ok((pk.key_id, PublicKey::deserialize(&pk.public_key)?))
                })
                .transpose()?,
            // pre_key: Option<(u32, PublicKey)>,
            self.signed_pre_key.key_id,
            PublicKey::deserialize(&self.signed_pre_key.public_key)?,
            self.signed_pre_key.signature,
            identity,
        )
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
    #[serde(with = "serde_optional_base64")]
    pub name: Option<Vec<u8>>,
    #[serde(with = "serde_optional_base64")]
    pub about: Option<Vec<u8>>,
    #[serde(with = "serde_optional_base64")]
    pub about_emoji: Option<Vec<u8>>,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CdnUploadAttributes {
    path: String,
    acl: String,
    key: String,
    policy: String,
    algorithm: String,
    credential: String,
    date: String,
    signature: String,
    content_type: String,
    length: u64,
}

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV2UploadAttributes {
    url: Option<String>,
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
    attachment_id_string: String,
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

    #[error("{0:?}")]
    MismatchedDevicesException(MismatchedDevices),

    #[error("{0:?}")]
    StaleDevices(StaleDevices),

    #[error("SealedSessionCipher error: {0}")]
    SealedSessionError(
        #[from] crate::sealed_session_cipher::SealedSessionError,
    ),

    #[error(transparent)]
    CredentialsCacheError(#[from] crate::groups_v2::CredentialsCacheError),

    #[error("groups v2 (zero-knowledge) error")]
    GroupsV2Error,

    #[error(transparent)]
    GroupsV2DecryptionError(#[from] GroupDecryptionError),
}

#[async_trait::async_trait(?Send)]
pub trait PushService {
    type WebSocket: WebSocketService;
    type ByteStream: futures::io::AsyncRead + Unpin;

    async fn get_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn delete_json<T>(
        &mut self,
        service: Endpoint,
        path: &str,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn put_json<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize;

    async fn get_protobuf<T>(
        &mut self,
        service: Endpoint,
        path: &str,
        credentials_override: HttpAuthOverride,
    ) -> Result<T, ServiceError>
    where
        T: Default + ProtobufMessage;

    async fn put_protobuf<D, S>(
        &mut self,
        service: Endpoint,
        path: &str,
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
    ) -> Result<
        (
            Self::WebSocket,
            <Self::WebSocket as WebSocketService>::Stream,
        ),
        ServiceError,
    >;

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
                HttpAuthOverride::NoOverride,
            )
            .await?;

        Ok(devices.devices)
    }

    async fn unlink_device(&mut self, id: i64) -> Result<(), ServiceError> {
        self.delete_json(Endpoint::Service, &format!("/v1/devices/{}", id))
            .await
    }

    async fn get_pre_key_status(
        &mut self,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v2/keys/",
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn register_pre_keys(
        &mut self,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        match self
            .put_json(
                Endpoint::Service,
                "/v2/keys/",
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
            }
            AttachmentIdentifier::CdnKey(key) => {
                self.get_attachment_by_id(key, ptr.cdn_number()).await
            }
        }
    }

    async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.destination);
        self.put_json(
            Endpoint::Service,
            &path,
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
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn retrieve_profile_by_id(
        &mut self,
        id: &str,
    ) -> Result<SignalServiceProfile, ServiceError> {
        self.get_json(
            Endpoint::Service,
            &format!("/v1/profile/{}", id),
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    async fn get_pre_key(
        &mut self,
        destination: &ServiceAddress,
        device_id: u32,
    ) -> Result<PreKeyBundle, ServiceError> {
        let path = if let Some(ref relay) = destination.relay {
            format!(
                "/v2/keys/{}/{}?relay={}",
                destination.identifier(),
                device_id,
                relay
            )
        } else {
            format!("/v2/keys/{}/{}", destination.identifier(), device_id)
        };

        let mut pre_key_response: PreKeyResponse = self
            .get_json(Endpoint::Service, &path, HttpAuthOverride::NoOverride)
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
        let path = match (device_id, destination.relay.as_ref()) {
            (1, None) => format!("/v2/keys/{}/*", destination.identifier()),
            (device_id, None) => {
                format!("/v2/keys/{}/{}", destination.identifier(), device_id)
            }
            (1, Some(relay)) => format!(
                "/v2/keys/{}/*?relay={}",
                destination.identifier(),
                relay
            ),
            (device_id, Some(relay)) => format!(
                "/v2/keys/{}/{}?relay={}",
                destination.identifier(),
                device_id,
                relay
            ),
        };
        let pre_key_response: PreKeyResponse = self
            .get_json(Endpoint::Service, &path, HttpAuthOverride::NoOverride)
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
            HttpAuthOverride::Identified(credentials),
        )
        .await
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
    /// The name, about and emoji fields are encrypted with an [`ProfileCipher`].
    /// See [`AccountManager`] for a convenience method.
    ///
    /// Java equivalent: `writeProfile`
    async fn write_profile(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        commitment: &ProfileKeyCommitment,
        // FIXME cfr also account manager
        avatar: Option<()>,
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
            avatar: avatar.is_some(),
            commitment: &commitment,
        };

        // XXX this should  be a struct; cfr ProfileAvatarUploadAttributes
        let response: Result<String, _> = self
            .put_json(
                Endpoint::Service,
                "/v1/profile",
                HttpAuthOverride::NoOverride,
                command,
            )
            .await;
        match (response, avatar) {
            (Ok(_url), Some(_avatar)) => {
                // FIXME
                unreachable!("Uploading avatar unimplemented");
            }
            // FIXME cleanup when #54883 is stable and MSRV:
            // or-patterns syntax is experimental
            // see issue #54883 <https://github.com/rust-lang/rust/issues/54883> for more information
            (Err(ServiceError::JsonDecodeError { .. }), None) => {
                // OWS sends an empty string when there's no attachment
                Ok(None)
            }
            (Err(e), _) => Err(e),
            (Ok(_resp), None) => {
                log::warn!(
                    "No avatar supplied but got avatar upload URL. Ignoring"
                );
                Ok(None)
            }
        }
    }
}
