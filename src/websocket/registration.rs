use libsignal_protocol::IdentityKey;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::ServiceError;
use crate::{
    pre_keys::{KyberPreKeyEntity, SignedPreKeyEntity},
    utils::serde_base64,
    websocket::{self, account::AccountAttributes, SignalWebSocket},
};

/// This type is used in registration lock handling.
/// It's identical with HttpAuth, but used to avoid type confusion.
#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    pub username: String,
    #[debug(ignore)]
    pub password: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationTransport {
    Sms,
    Voice,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceActivationRequest {
    pub aci_signed_pre_key: SignedPreKeyEntity,
    pub pni_signed_pre_key: SignedPreKeyEntity,
    pub aci_pq_last_resort_pre_key: KyberPreKeyEntity,
    pub pni_pq_last_resort_pre_key: KyberPreKeyEntity,
}

#[derive(Debug, Serialize)]
pub struct CaptchaAttributes<'a> {
    #[serde(rename = "type")]
    pub challenge_type: &'a str,
    pub token: &'a str,
    pub captcha: &'a str,
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

impl SignalWebSocket<websocket::Unidentified> {
    // Equivalent of Java's
    // RegistrationSessionMetadataResponse createVerificationSession(@Nullable String pushToken, @Nullable String mcc, @Nullable String mnc)
    pub async fn create_verification_session<'a>(
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

        self.http_request(Method::POST, "/v1/verification/session")?
            .send_json(&VerificationSessionMetadataRequestBody {
                number,
                push_token_type: push_token.as_ref().map(|_| "fcm"),
                push_token,
                mcc,
                mnc,
            })
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }

    pub async fn patch_verification_session<'a>(
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

        self.http_request(
            Method::PATCH,
            format!("/v1/verification/session/{}", session_id),
        )?
        .send_json(&UpdateVerificationSessionRequestBody {
            captcha,
            push_token_type: push_token.as_ref().map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
            push_challenge,
        })
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }

    // Equivalent of Java's
    // RegistrationSessionMetadataResponse requestVerificationCode(String sessionId, Locale locale, boolean androidSmsRetriever, VerificationCodeTransport transport)
    /// Request a verification code.
    ///
    /// Signal requires a client type, and they use these three strings internally:
    ///   - "android-2021-03"
    ///   - "android"
    ///   - "ios"
    ///
    /// "android-2021-03" allegedly implies FCM support, whereas the other strings don't. In
    /// principle, they will consider any string as "unknown", so other strings may work too.
    pub async fn request_verification_code(
        &mut self,
        session_id: &str,
        client: &str,
        // XXX: We currently don't support this, because we need to set some headers in the
        //      post_json() call
        // locale: Option<String>,
        transport: VerificationTransport,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Debug, Serialize)]
        struct VerificationCodeRequest<'a> {
            transport: VerificationTransport,
            client: &'a str,
        }

        self.http_request(
            Method::POST,
            format!("/v1/verification/session/{}/code", session_id),
        )?
        .send_json(&VerificationCodeRequest { transport, client })
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn submit_registration_request(
        &mut self,
        registration_method: RegistrationMethod<'_>,
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

        self.http_request(Method::POST, "/v1/registration")?
            .send_json(&RegistrationSessionRequestBody {
                session_id: registration_method.session_id(),
                recovery_password: registration_method.recovery_password(),
                account_attributes,
                skip_device_transfer,
                aci_identity_key: aci_identity_key.serialize().into(),
                pni_identity_key: pni_identity_key.serialize().into(),
                device_activation_request,
                every_signed_key_valid: true,
            })
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }

    pub async fn submit_verification_code(
        &mut self,
        session_id: &str,
        verification_code: &str,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Debug, Serialize)]
        struct VerificationCode<'a> {
            code: &'a str,
        }

        self.http_request(
            Method::PUT,
            format!("/v1/verification/session/{}/code", session_id),
        )?
        .send_json(&VerificationCode {
            code: verification_code,
        })
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }
}
