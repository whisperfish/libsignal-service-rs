use std::time::Duration;

use crate::{
    configuration::Credentials,
    envelope::*,
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

use libsignal_protocol::{keys::PublicKey, Context, PreKeyBundle};
use serde::{Deserialize, Serialize};

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
pub const DEFAULT_DEVICE_ID: i32 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum SmsVerificationCodeResponse {
    CaptchaRequired,
    SmsSent,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VoiceVerificationCodeResponse {
    CaptchaRequired,
    CallIssued,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    pub device_id: i32,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmDeviceMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub fetches_messages: bool,
    pub registration_id: u32,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    pub pin: Option<String>,
    #[serde(with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    pub capabilities: DeviceCapabilities,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    pub uuid: bool,
    pub gv2: bool,
    pub storage: bool,
}

pub struct ProfileKey(pub Vec<u8>);

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
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

impl ConfirmCodeMessage {
    pub fn new(
        signaling_key: Vec<u8>,
        registration_id: u32,
        unidentified_access_key: Vec<u8>,
    ) -> Self {
        Self {
            signaling_key,
            supports_sms: false,
            registration_id,
            voice: false,
            video: false,
            fetches_messages: true,
            pin: None,
            unidentified_access_key: Some(unidentified_access_key),
            unrestricted_unidentified_access: false,
            discoverable_by_phone_number: true,
            capabilities: DeviceCapabilities::default(),
        }
    }

    pub fn new_without_unidentified_access(
        signaling_key: Vec<u8>,
        registration_id: u32,
    ) -> Self {
        Self {
            signaling_key,
            supports_sms: false,
            registration_id,
            voice: false,
            video: false,
            fetches_messages: true,
            pin: None,
            unidentified_access_key: None,
            unrestricted_unidentified_access: false,
            discoverable_by_phone_number: true,
            capabilities: DeviceCapabilities::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeResponse {
    pub uuid: String,
    pub storage_capable: bool,
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
    pub uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    pub device_id: i32,
    pub registration_id: u32,
    pub signed_pre_key: Option<SignedPreKeyEntity>,
    pub pre_key: Option<PreKeyEntity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    pub missing_devices: Vec<i32>,
    pub extra_devices: Vec<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    pub stale_devices: Vec<i32>,
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

    #[error("Error sending request: {reason}")]
    SendError { reason: String },
    #[error("Error decoding JSON response: {reason}")]
    JsonDecodeError { reason: String },

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

    #[error("Undecodable frame: {0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Invalid frame: {reason}")]
    InvalidFrameError { reason: String },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] libsignal_protocol::Error),

    #[error("{0:?}")]
    MismatchedDevicesException(MismatchedDevices),

    #[error("{0:?}")]
    StaleDevices(StaleDevices),

    #[error("SealedSessionCipher error: {0}")]
    SealedSessionError(
        #[from] crate::sealed_session_cipher::SealedSessionError,
    ),
}

#[async_trait::async_trait(?Send)]
pub trait PushService {
    type WebSocket: WebSocketService;
    type ByteStream: futures::io::AsyncRead + Unpin;

    async fn get<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn delete<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn put<D, S>(
        &mut self,
        path: &str,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize;

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

    async fn request_sms_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        match self
            .get(&format!("/v1/accounts/sms/code/{}", phone_number))
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        }?;
        Ok(SmsVerificationCodeResponse::SmsSent)
    }

    async fn request_voice_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        match self
            .get(&format!("/v1/accounts/voice/code/{}", phone_number))
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        }?;
        Ok(VoiceVerificationCodeResponse::CallIssued)
    }

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    async fn devices(&mut self) -> Result<Vec<DeviceInfo>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct DeviceInfoList {
            devices: Vec<DeviceInfo>,
        }

        let devices: DeviceInfoList = self.get("/v1/devices/").await?;

        Ok(devices.devices)
    }

    async fn confirm_verification_code(
        &mut self,
        confirm_code: u32,
        confirm_verification_message: ConfirmCodeMessage,
    ) -> Result<ConfirmCodeResponse, ServiceError> {
        self.put(
            &format!("/v1/accounts/code/{}", confirm_code),
            confirm_verification_message,
        )
        .await
    }

    async fn confirm_device(
        &mut self,
        confirm_code: u32,
        confirm_code_message: ConfirmDeviceMessage,
    ) -> Result<DeviceId, ServiceError> {
        self.put(
            &format!("/v1/devices/{}", confirm_code),
            confirm_code_message,
        )
        .await
    }

    async fn get_pre_key_status(
        &mut self,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.get("/v2/keys/").await
    }

    async fn register_pre_keys(
        &mut self,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        match self.put("/v2/keys/", pre_key_state).await {
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

    async fn send_messages<'a>(
        &mut self,
        messages: OutgoingPushMessages<'a>,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.destination);
        self.put(&path, messages).await
    }

    /// Request AttachmentV2UploadAttributes
    ///
    /// Equivalent with getAttachmentV2UploadAttributes
    async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.get("/v2/attachments/form/upload").await
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
        let entity_list: EnvelopeEntityList = self.get("/v1/messages/").await?;
        Ok(entity_list.messages)
    }

    /// Method used to check our own UUID
    async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        self.get("/v1/accounts/whoami").await
    }

    async fn get_pre_key(
        &mut self,
        context: &Context,
        destination: &ServiceAddress,
        device_id: i32,
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

        let mut pre_key_response: PreKeyResponse = self.get(&path).await?;
        assert!(!pre_key_response.devices.is_empty());

        let device = pre_key_response.devices.remove(0);
        let mut bundle = PreKeyBundle::builder()
            .identity_key(&PublicKey::decode_point(
                &context,
                &pre_key_response.identity_key,
            )?)
            .device_id(device.device_id)
            .registration_id(device.registration_id);
        if let Some(signed_pre_key) = device.signed_pre_key {
            bundle = bundle.signed_pre_key(
                signed_pre_key.key_id,
                &PublicKey::decode_point(&context, &signed_pre_key.public_key)?,
            );
            bundle = bundle.signature(&signed_pre_key.signature);
        }
        if let Some(pre_key) = device.pre_key {
            bundle = bundle.pre_key(
                pre_key.key_id,
                &PublicKey::decode_point(context, &pre_key.public_key)?,
            );
        }
        Ok(bundle.build()?)
    }

    async fn get_pre_keys(
        &mut self,
        context: &Context,
        destination: &ServiceAddress,
        device_id: i32,
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
        let pre_key_response: PreKeyResponse = self.get(&path).await?;
        let mut pre_keys = vec![];
        for device in pre_key_response.devices {
            let mut bundle = PreKeyBundle::builder()
                .identity_key(&PublicKey::decode_point(
                    &context,
                    &pre_key_response.identity_key,
                )?)
                .device_id(device.device_id)
                .registration_id(device.registration_id);
            if let Some(signed_pre_key) = device.signed_pre_key {
                bundle = bundle.signed_pre_key(
                    signed_pre_key.key_id,
                    &PublicKey::decode_point(
                        &context,
                        &signed_pre_key.public_key,
                    )?,
                );
                bundle = bundle.signature(&signed_pre_key.signature);
            }
            if let Some(pre_key) = device.pre_key {
                bundle = bundle.pre_key(
                    pre_key.key_id,
                    &PublicKey::decode_point(context, &pre_key.public_key)?,
                );
            }
            pre_keys.push(bundle.build()?)
        }
        Ok(pre_keys)
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
    >;
}
