use crate::{
    configuration::{Credentials, ServiceConfiguration},
    envelope::*,
};

use http::StatusCode;
use serde::Deserialize;

pub const CREATE_ACCOUNT_SMS_PATH: &str = "/v1/accounts/sms/code/%s?client=%s";
pub const CREATE_ACCOUNT_VOICE_PATH: &str = "/v1/accounts/voice/code/%s";
pub const VERIFY_ACCOUNT_CODE_PATH: &str = "/v1/accounts/code/%s";
pub const REGISTER_GCM_PATH: &str = "/v1/accounts/gcm/";
pub const TURN_SERVER_INFO: &str = "/v1/accounts/turn";
pub const SET_ACCOUNT_ATTRIBUTES: &str = "/v1/accounts/attributes/";
pub const PIN_PATH: &str = "/v1/accounts/pin/";
pub const REQUEST_PUSH_CHALLENGE: &str = "/v1/accounts/fcm/preauth/%s/%s";
pub const WHO_AM_I: &str = "/v1/accounts/whoami";

pub const PREKEY_METADATA_PATH: &str = "/v2/keys/";
pub const PREKEY_PATH: &str = "/v2/keys/%s";
pub const PREKEY_DEVICE_PATH: &str = "/v2/keys/%s/%s";
pub const SIGNED_PREKEY_PATH: &str = "/v2/keys/signed";

pub const PROVISIONING_CODE_PATH: &str = "/v1/devices/provisioning/code";
pub const PROVISIONING_MESSAGE_PATH: &str = "/v1/provisioning/%s";
pub const DEVICE_PATH: &str = "/v1/devices/%s";

pub const DIRECTORY_TOKENS_PATH: &str = "/v1/directory/tokens";
pub const DIRECTORY_VERIFY_PATH: &str = "/v1/directory/%s";
pub const DIRECTORY_AUTH_PATH: &str = "/v1/directory/auth";
pub const DIRECTORY_FEEDBACK_PATH: &str = "/v1/directory/feedback-v3/%s";
pub const MESSAGE_PATH: &str = "/v1/messages/"; // optionally with destination appended
pub const SENDER_ACK_MESSAGE_PATH: &str = "/v1/messages/%s/%d";
pub const UUID_ACK_MESSAGE_PATH: &str = "/v1/messages/uuid/%s";
pub const ATTACHMENT_PATH: &str = "/v2/attachments/form/upload";

pub const PROFILE_PATH: &str = "/v1/profile/%s";

pub const SENDER_CERTIFICATE_LEGACY_PATH: &str = "/v1/certificate/delivery";
pub const SENDER_CERTIFICATE_PATH: &str =
    "/v1/certificate/delivery?includeUuid=true";

pub const ATTACHMENT_DOWNLOAD_PATH: &str = "attachments/%d";
pub const ATTACHMENT_UPLOAD_PATH: &str = "attachments/";

pub const STICKER_MANIFEST_PATH: &str = "stickers/%s/manifest.proto";
pub const STICKER_PATH: &str = "stickers/%s/full/%d";

pub enum SmsVerificationCodeResponse {
    CaptchaRequired,
    SmsSent,
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
}

impl ServiceError {
    pub fn from_status(code: http::StatusCode) -> Result<(), Self> {
        match code {
            StatusCode::OK => Ok(()),
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(ServiceError::Unauthorized)
            },
            StatusCode::PAYLOAD_TOO_LARGE => {
                // This is 413 and means rate limit exceeded for Signal.
                Err(ServiceError::RateLimitExceeded)
            },
            // XXX: fill in rest from PushServiceSocket
            _ => Err(ServiceError::UnhandledResponseCode {
                http_code: code.as_u16(),
            }),
        }
    }
}

#[async_trait::async_trait(?Send)]
pub trait PushService {
    type WebSocket;

    async fn get<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>;

    async fn request_sms_verification_code(
        &mut self,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        self.get(CREATE_ACCOUNT_SMS_PATH).await?;
        Ok(SmsVerificationCodeResponse::SmsSent)
    }

    async fn get_messages(
        &mut self,
    ) -> Result<Vec<EnvelopeEntity>, ServiceError> {
        let entity_list: EnvelopeEntityList = self.get(MESSAGE_PATH).await?;
        Ok(entity_list.messages)
    }

    async fn ws(&mut self) -> Result<Self::WebSocket, ServiceError>;
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
    type WebSocket = ();

    async fn get<T>(&mut self, _path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        unimplemented!()
    }

    async fn ws(&mut self) -> Result<Self::WebSocket, ServiceError> {
        unimplemented!()
    }
}
