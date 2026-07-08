use libsignal_protocol::IdentityKeyStore;
use rand::{CryptoRng, Rng};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tracing::Instrument;
use uuid::Uuid;

use super::ServiceError;
use crate::{
    pre_keys::{KyberPreKeyEntity, PreKeysStore, SignedPreKeyEntity},
    provisioning::ProvisioningError,
    utils::{serde_base64, TryIntoE164},
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
pub struct RegistrationKeyPackage {
    pub aci_identity_key: Vec<u8>,
    pub pni_identity_key: Vec<u8>,
    pub aci_signed_pre_key: SignedPreKeyEntity,
    pub pni_signed_pre_key: SignedPreKeyEntity,
    pub aci_pq_last_resort_pre_key: KyberPreKeyEntity,
    pub pni_pq_last_resort_pre_key: KyberPreKeyEntity,
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
pub struct GcmRegistrationId<'a> {
    pub gcm_registration_id: &'a str,
    pub web_socket_channel: bool,
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

    pub async fn submit_registration_request(
        &mut self,
        registration_method: RegistrationMethod<'_>,
        phonenumber: impl TryIntoE164,
        password: &str,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
        keys: RegistrationKeyPackage,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        /// https://github.com/signalapp/Signal-Android/blob/main/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/RegistrationSessionRequestBody.kt
        struct RegistrationSessionRequestBody<'a> {
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: AccountAttributes,
            skip_device_transfer: bool,
            #[serde(default, with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            #[serde(default, with = "serde_base64")]
            aci_identity_key: Vec<u8>,
            aci_signed_pre_key: SignedPreKeyEntity,
            pni_signed_pre_key: SignedPreKeyEntity,
            aci_pq_last_resort_pre_key: KyberPreKeyEntity,
            pni_pq_last_resort_pre_key: KyberPreKeyEntity,
            gcm_token: Option<GcmRegistrationId<'a>>,
            require_atomic: bool,
        }

        let phonenumber = phonenumber
            .try_into_e164()
            .map_err(|_| ServiceError::InvalidPhoneNumber)?;

        self.http_request(Method::POST, "/v1/registration")?
            .registration_auth_header(phonenumber, password)
            .send_json(&RegistrationSessionRequestBody {
                session_id: registration_method.session_id(),
                recovery_password: registration_method.recovery_password(),
                account_attributes,
                skip_device_transfer,
                aci_identity_key: keys.aci_identity_key,
                pni_identity_key: keys.pni_identity_key,
                aci_signed_pre_key: keys.aci_signed_pre_key,
                pni_signed_pre_key: keys.pni_signed_pre_key,
                aci_pq_last_resort_pre_key: keys.aci_pq_last_resort_pre_key,
                pni_pq_last_resort_pre_key: keys.pni_pq_last_resort_pre_key,
                gcm_token: None,
                require_atomic: true, // XXX default = true but what does this signify?
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

    #[allow(clippy::too_many_arguments)]
    pub async fn register_account<
        R: Rng + CryptoRng,
        Aci: PreKeysStore + IdentityKeyStore,
        Pni: PreKeysStore + IdentityKeyStore,
    >(
        &mut self,
        csprng: &mut R,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        aci_protocol_store: &mut Aci,
        pni_protocol_store: &mut Pni,
        skip_device_transfer: bool,
        phonenumber: impl TryIntoE164,
        password: &str,
    ) -> Result<VerifyAccountResponse, ProvisioningError> {
        let aci_identity_key_pair = aci_protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get ACI identity key pair"))
            .await?;
        let pni_identity_key_pair = pni_protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get PNI identity key pair"))
            .await?;

        let (
            _aci_pre_keys,
            aci_signed_pre_key,
            _aci_kyber_pre_keys,
            aci_last_resort_kyber_prekey,
        ) = crate::pre_keys::replenish_pre_keys(
            aci_protocol_store,
            csprng,
            &aci_identity_key_pair,
            true,
            0,
            0,
        )
        .await?;

        let (
            _pni_pre_keys,
            pni_signed_pre_key,
            _pni_kyber_pre_keys,
            pni_last_resort_kyber_prekey,
        ) = crate::pre_keys::replenish_pre_keys(
            pni_protocol_store,
            csprng,
            &pni_identity_key_pair,
            true,
            0,
            0,
        )
        .await?;

        let aci_identity_key = aci_identity_key_pair.identity_key();
        let pni_identity_key = pni_identity_key_pair.identity_key();
        let keys = RegistrationKeyPackage {
            aci_identity_key: aci_identity_key.serialize().into(),
            pni_identity_key: pni_identity_key.serialize().into(),
            aci_signed_pre_key: SignedPreKeyEntity::try_from(
                &aci_signed_pre_key,
            )
            .unwrap(),
            pni_signed_pre_key: pni_signed_pre_key.try_into()?,
            aci_pq_last_resort_pre_key: aci_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
            pni_pq_last_resort_pre_key: pni_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
        };

        let result = self
            .submit_registration_request(
                registration_method,
                phonenumber,
                password,
                account_attributes,
                skip_device_transfer,
                keys,
            )
            .await?;

        Ok(result)
    }
}
