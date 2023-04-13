use std::time::Duration;

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    envelope::*,
    groups_v2::GroupDecodingError,
    pre_keys::{PreKeyEntity, PreKeyState, SignedPreKeyEntity},
    profile_cipher::ProfileCipherError,
    proto::{attachment_pointer::AttachmentIdentifier, AttachmentPointer},
    sender::{OutgoingPushMessages, SendMessageResponse},
    utils::{serde_base64, serde_optional_base64},
    websocket::SignalWebSocket,
    MaybeSend, ParseServiceAddressError, Profile, ServiceAddress,
};

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, NewAead,
};
use chrono::prelude::*;
use derivative::Derivative;
use libsignal_protocol::{
    error::SignalProtocolError, IdentityKey, PreKeyBundle, PublicKey,
    SenderCertificate,
};
use prost::Message as ProtobufMessage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::profiles::{ProfileKey, ProfileKeyCommitment, ProfileKeyVersion};

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
    #[serde(default, with = "serde_optional_base64")]
    pub signaling_key: Option<Vec<u8>>,
    pub registration_id: u32,
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
    pub name: String,
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

pub trait ProfileKeyExt {
    fn derive_access_key(&self) -> Vec<u8>;
}

impl ProfileKeyExt for ProfileKey {
    fn derive_access_key(&self) -> Vec<u8> {
        let key = GenericArray::from_slice(&self.bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let buf = [0u8; 16];
        let mut ciphertext = cipher.encrypt(nonce, &buf[..]).unwrap();
        ciphertext.truncate(16);
        ciphertext
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
    pub(crate) fn into_bundle(
        self,
        identity: IdentityKey,
    ) -> Result<PreKeyBundle, SignalProtocolError> {
        PreKeyBundle::new(
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

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
pub trait PushService: MaybeSend {
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
        S: MaybeSend + Serialize;

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
            },
            AttachmentIdentifier::CdnKey(key) => {
                self.get_attachment_by_id(key, ptr.cdn_number()).await
            },
        }
    }

    async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.recipient.uuid);
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
        let path = format!("/v2/keys/{}/{}", destination.uuid, device_id);

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
        let path = if device_id == 1 {
            format!("/v2/keys/{}/*", destination.uuid)
        } else {
            format!("/v2/keys/{}/{}", destination.uuid, device_id)
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

    async fn get_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .get_json(
                Endpoint::Service,
                "/v1/certificate/delivery",
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
}
