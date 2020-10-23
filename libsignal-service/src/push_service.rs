use std::time::Duration;

use crate::{
    configuration::{Credentials, ServiceConfiguration},
    envelope::*,
    messagepipe::WebSocketService,
    pre_keys::PreKeyState,
    proto::{attachment_pointer::AttachmentIdentifier, AttachmentPointer},
    utils::serde_base64,
};

use aes::block_cipher::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, NewAead};
use http::StatusCode;
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

pub enum SmsVerificationCodeResponse {
    CaptchaRequired,
    SmsSent,
}

pub enum VoiceVerificationCodeResponse {
    CaptchaRequired,
    CallIssued,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    pub device_id: u32,
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
    signaling_key: Vec<u8>,
    supports_sms: bool,
    registration_id: u32,
    voice: bool,
    video: bool,
    fetches_messages: bool,
    pin: Option<String>,
    #[serde(with = "serde_base64")]
    unidentified_access_key: Vec<u8>,
    unrestricted_unidentified_access: bool,
    discoverable_by_phone_number: bool,
    capabilities: DeviceCapabilities,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct DeviceCapabilities {
    uuid: bool,
    gv2: bool,
    storage: bool,
}

pub struct ProfileKey(pub Vec<u8>);

impl ProfileKey {
    pub fn derive_access_key(&self) -> Result<Vec<u8>, aes_gcm::Error> {
        let key = GenericArray::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(&[0u8; 12]);
        let buf = [0u8; 16];
        cipher.encrypt(nonce, &buf[..])
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
            unidentified_access_key,
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

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
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

    #[error("Undecodable frame")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Invalid frame: {reason}")]
    InvalidFrameError { reason: String },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] libsignal_protocol::Error),
}

impl ServiceError {
    pub fn from_status(code: http::StatusCode) -> Result<(), Self> {
        match code {
            StatusCode::OK => Ok(()),
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(ServiceError::Unauthorized)
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                // This is 413 and means rate limit exceeded for Signal.
                Err(ServiceError::RateLimitExceeded)
            }
            // XXX: fill in rest from PushServiceSocket
            _ => Err(ServiceError::UnhandledResponseCode {
                http_code: code.as_u16(),
            }),
        }
    }
}

#[async_trait::async_trait(?Send)]
pub trait PushService {
    type WebSocket: WebSocketService;
    type ByteStream: futures::io::AsyncRead + Unpin;

    async fn get<T>(&mut self, path: &str) -> Result<T, ServiceError>
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

    async fn get_messages(
        &mut self,
    ) -> Result<Vec<EnvelopeEntity>, ServiceError> {
        let entity_list: EnvelopeEntityList = self.get("/v1/messages/").await?;
        Ok(entity_list.messages)
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

/// PushService that panics on every request, mainly for example code.
pub struct PanicingPushService;

impl PanicingPushService {
    /// A PushService implementation typically takes a ServiceConfiguration,
    /// credentials and a user agent.
    pub fn new(
        _cfg: ServiceConfiguration,
        _credentials: Credentials,
        _user_agent: &str,
    ) -> Self {
        Self
    }
}

#[async_trait::async_trait(?Send)]
impl PushService for PanicingPushService {
    type ByteStream = Box<dyn futures::io::AsyncRead + Unpin>;
    type WebSocket = crate::messagepipe::PanicingWebSocketService;

    async fn get<T>(&mut self, _path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        unimplemented!()
    }

    async fn put<D, S>(
        &mut self,
        _path: &str,
        _value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize,
    {
        unimplemented!()
    }

    async fn get_from_cdn(
        &mut self,
        _cdn_id: u32,
        _path: &str,
    ) -> Result<Self::ByteStream, ServiceError> {
        unimplemented!()
    }

    async fn ws(
        &mut self,
        _path: &str,
        _credentials: Option<Credentials>,
    ) -> Result<
        (
            Self::WebSocket,
            <Self::WebSocket as WebSocketService>::Stream,
        ),
        ServiceError,
    > {
        unimplemented!()
    }
}
