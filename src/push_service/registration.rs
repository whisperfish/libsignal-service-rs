use libsignal_protocol::IdentityKey;
use reqwest::Method;
use serde::Serialize;

use crate::{
    configuration::Endpoint,
    push_service::{HttpAuthOverride, PushService, ReqwestExt, ServiceError},
    utils::{serde_base64, serde_optional_base64, serde_optional_prost_base64},
    websocket::{
        account::{AccountAttributes, DeviceCapabilities},
        registration::{
            DeviceActivationRequest, RegistrationMethod,
            RegistrationSessionMetadataResponse, VerificationTransport,
            VerifyAccountResponse,
        },
    },
};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RegistrationAccountAttributesBody {
    fetches_messages: bool,
    registration_id: u32,
    pni_registration_id: u32,
    #[serde(default, with = "serde_optional_prost_base64")]
    name: Option<crate::proto::DeviceName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registration_lock: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    unidentified_access_key: Option<Vec<u8>>,
    unrestricted_unidentified_access: bool,
    capabilities: DeviceCapabilities,
    discoverable_by_phone_number: bool,
    #[serde(
        default,
        with = "serde_optional_base64",
        skip_serializing_if = "Option::is_none"
    )]
    recovery_password: Option<Vec<u8>>,
}

impl From<AccountAttributes> for RegistrationAccountAttributesBody {
    fn from(account_attributes: AccountAttributes) -> Self {
        let AccountAttributes {
            fetches_messages,
            registration_id,
            pni_registration_id,
            name,
            registration_lock,
            unidentified_access_key,
            unrestricted_unidentified_access,
            capabilities,
            discoverable_by_phone_number,
            pin: _,
            recovery_password,
        } = account_attributes;

        Self {
            fetches_messages,
            registration_id,
            pni_registration_id,
            name,
            registration_lock,
            unidentified_access_key,
            unrestricted_unidentified_access,
            capabilities,
            discoverable_by_phone_number,
            recovery_password,
        }
    }
}

/// Direct HTTP helpers for registration-related service endpoints.
///
/// Signal-Android performs registration against ordinary HTTP endpoints on the
/// service API, not through the websocket request framing abstraction. These
/// helpers mirror that transport choice so higher-level registration flows can
/// avoid websocket-specific behavior while still using the shared `PushService`
/// client and auth handling.
///
/// The expected usage is:
///
/// 1. create / patch verification session
/// 2. request verification code
/// 3. submit verification code
/// 4. submit final registration request
///
/// When `PushService` is constructed with `ServiceCredentials`, the `NoOverride`
/// auth mode below will include the same basic-auth credentials that the normal
/// service request path uses.
impl PushService {
    /// Create a registration verification session via direct HTTP.
    ///
    /// `POST /v1/verification/session`
    pub async fn create_verification_session_direct<'a>(
        &mut self,
        number: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct VerificationSessionMetadataRequestBody<'a> {
            number: &'a str,
            push_token: Option<&'a str>,
            push_token_type: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
        }

        let response = self
            .request(
                Method::POST,
                Endpoint::service("/v1/verification/session"),
                HttpAuthOverride::NoOverride,
            )?
            .json(&VerificationSessionMetadataRequestBody {
                number,
                push_token,
                push_token_type: push_token.as_ref().map(|_| "fcm"),
                mcc,
                mnc,
            })
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response
            .json::<RegistrationSessionMetadataResponse>()
            .await
            .map_err(ServiceError::from)
    }

    /// Patch a registration verification session via direct HTTP.
    ///
    /// `PATCH /v1/verification/session/{session-id}`
    pub async fn patch_verification_session_direct<'a>(
        &mut self,
        session_id: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
        captcha: Option<&'a str>,
        push_challenge: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct UpdateVerificationSessionRequestBody<'a> {
            captcha: Option<&'a str>,
            push_token: Option<&'a str>,
            push_token_type: Option<&'a str>,
            push_challenge: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
        }

        let response = self
            .request(
                Method::PATCH,
                Endpoint::service(format!(
                    "/v1/verification/session/{session_id}"
                )),
                HttpAuthOverride::NoOverride,
            )?
            .json(&UpdateVerificationSessionRequestBody {
                captcha,
                push_token,
                push_token_type: push_token.as_ref().map(|_| "fcm"),
                push_challenge,
                mcc,
                mnc,
            })
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response
            .json::<RegistrationSessionMetadataResponse>()
            .await
            .map_err(ServiceError::from)
    }

    /// Request an SMS or voice verification code via direct HTTP.
    ///
    /// `POST /v1/verification/session/{session-id}/code`
    ///
    /// Signal expects a client string. Signal-Android uses:
    /// - `android-2021-03` when SMS Retriever support is enabled
    /// - `android` otherwise
    pub async fn request_verification_code_direct(
        &mut self,
        session_id: &str,
        client: &str,
        transport: VerificationTransport,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize, Debug)]
        struct VerificationCodeRequest<'a> {
            transport: VerificationTransport,
            client: &'a str,
        }

        let response = self
            .request(
                Method::POST,
                Endpoint::service(format!(
                    "/v1/verification/session/{session_id}/code"
                )),
                HttpAuthOverride::NoOverride,
            )?
            .json(&VerificationCodeRequest { transport, client })
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response
            .json::<RegistrationSessionMetadataResponse>()
            .await
            .map_err(ServiceError::from)
    }

    /// Submit a verification code via direct HTTP.
    ///
    /// `PUT /v1/verification/session/{session-id}/code`
    pub async fn submit_verification_code_direct(
        &mut self,
        session_id: &str,
        verification_code: &str,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize, Debug)]
        struct VerificationCode<'a> {
            code: &'a str,
        }

        let response = self
            .request(
                Method::PUT,
                Endpoint::service(format!(
                    "/v1/verification/session/{session_id}/code"
                )),
                HttpAuthOverride::NoOverride,
            )?
            .json(&VerificationCode {
                code: verification_code,
            })
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response
            .json::<RegistrationSessionMetadataResponse>()
            .await
            .map_err(ServiceError::from)
    }

    /// Submit the final registration request via direct HTTP.
    ///
    /// `POST /v1/registration`
    ///
    /// This intentionally mirrors the transport used by Signal-Android's
    /// `PushServiceSocket.submitRegistrationRequest(...)`.
    pub async fn submit_registration_request_direct(
        &mut self,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
        aci_identity_key: &IdentityKey,
        pni_identity_key: &IdentityKey,
        device_activation_request: DeviceActivationRequest,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct RegistrationSessionRequestBody<'a> {
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: RegistrationAccountAttributesBody,
            skip_device_transfer: bool,
            every_signed_key_valid: bool,
            #[serde(default, with = "serde_base64")]
            aci_identity_key: Vec<u8>,
            #[serde(default, with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            #[serde(flatten)]
            device_activation_request: DeviceActivationRequest,
        }

        let response = self
            .request(
                Method::POST,
                Endpoint::service("/v1/registration"),
                HttpAuthOverride::NoOverride,
            )?
            .json(&RegistrationSessionRequestBody {
                session_id: registration_method.session_id(),
                recovery_password: registration_method.recovery_password(),
                account_attributes: account_attributes.into(),
                skip_device_transfer,
                every_signed_key_valid: true,
                aci_identity_key: aci_identity_key.serialize().into(),
                pni_identity_key: pni_identity_key.serialize().into(),
                device_activation_request,
            })
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response
            .json::<VerifyAccountResponse>()
            .await
            .map_err(ServiceError::from)
    }
}
