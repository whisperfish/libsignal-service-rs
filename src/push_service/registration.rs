use libsignal_protocol::{IdentityKey, IdentityKeyStore};
use rand::{CryptoRng, Rng};
use reqwest::Method;
use serde::Serialize;
use tracing_futures::Instrument;

use crate::{
    configuration::Endpoint,
    pre_keys::PreKeysStore,
    provisioning::ProvisioningError,
    utils::serde_base64,
    websocket::{
        account::AccountAttributes,
        registration::{
            DeviceActivationRequest, RegistrationMethod,
            RegistrationSessionMetadataResponse, VerificationTransport,
            VerifyAccountResponse,
        },
    },
};

use super::{response::ReqwestExt, HttpAuthOverride, PushService, ServiceError};

impl PushService {
    /// Create a new verification session for registration.
    pub async fn create_verification_session<'a>(
        &self,
        number: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            number: &'a str,
            push_token: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        self.request(
            Method::POST,
            Endpoint::service("/v1/verification/session"),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            number,
            push_token_type: push_token.as_ref().map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Patch an existing verification session (e.g. to submit a captcha).
    pub async fn patch_verification_session<'a>(
        &self,
        session_id: &'a str,
        push_token: Option<&'a str>,
        mcc: Option<&'a str>,
        mnc: Option<&'a str>,
        captcha: Option<&'a str>,
        push_challenge: Option<&'a str>,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            captcha: Option<&'a str>,
            push_token: Option<&'a str>,
            push_challenge: Option<&'a str>,
            mcc: Option<&'a str>,
            mnc: Option<&'a str>,
            push_token_type: Option<&'a str>,
        }

        self.request(
            Method::PATCH,
            Endpoint::service(format!(
                "/v1/verification/session/{session_id}"
            )),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            captcha,
            push_token_type: push_token.as_ref().map(|_| "fcm"),
            push_token,
            mcc,
            mnc,
            push_challenge,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Request a verification code via SMS or voice call.
    pub async fn request_verification_code(
        &self,
        session_id: &str,
        client: &str,
        transport: VerificationTransport,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        struct Body<'a> {
            transport: VerificationTransport,
            client: &'a str,
        }

        self.request(
            Method::POST,
            Endpoint::service(format!(
                "/v1/verification/session/{session_id}/code"
            )),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body { transport, client })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Submit a verification code received via SMS or voice call.
    pub async fn submit_verification_code(
        &self,
        session_id: &str,
        verification_code: &str,
    ) -> Result<RegistrationSessionMetadataResponse, ServiceError> {
        #[derive(Serialize)]
        struct Body<'a> {
            code: &'a str,
        }

        self.request(
            Method::PUT,
            Endpoint::service(format!(
                "/v1/verification/session/{session_id}/code"
            )),
            HttpAuthOverride::Unidentified,
        )?
        .json(&Body {
            code: verification_code,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Submit a registration request to create a new account.
    pub async fn submit_registration_request(
        &self,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        skip_device_transfer: bool,
        aci_identity_key: &IdentityKey,
        pni_identity_key: &IdentityKey,
        device_activation_request: DeviceActivationRequest,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            session_id: Option<&'a str>,
            recovery_password: Option<&'a str>,
            account_attributes: AccountAttributes,
            skip_device_transfer: bool,
            every_signed_key_valid: bool,
            #[serde(with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            #[serde(with = "serde_base64")]
            aci_identity_key: Vec<u8>,
            #[serde(flatten)]
            device_activation_request: DeviceActivationRequest,
        }

        self.request(
            Method::POST,
            Endpoint::service("/v1/registration"),
            HttpAuthOverride::NoOverride,
        )?
        .json(&Body {
            session_id: registration_method.session_id(),
            recovery_password: registration_method.recovery_password(),
            account_attributes,
            skip_device_transfer,
            aci_identity_key: aci_identity_key.serialize().into(),
            pni_identity_key: pni_identity_key.serialize().into(),
            device_activation_request,
            every_signed_key_valid: true,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Register a new account: generates pre-keys and submits the registration request.
    ///
    /// This is a convenience method that combines pre-key generation with
    /// [`submit_registration_request`](Self::submit_registration_request).
    pub async fn register_account<
        R: Rng + CryptoRng,
        Aci: PreKeysStore + IdentityKeyStore,
        Pni: PreKeysStore + IdentityKeyStore,
    >(
        &self,
        csprng: &mut R,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        aci_protocol_store: &mut Aci,
        pni_protocol_store: &mut Pni,
        skip_device_transfer: bool,
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

        let dar = DeviceActivationRequest {
            aci_signed_pre_key: aci_signed_pre_key.try_into()?,
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
                account_attributes,
                skip_device_transfer,
                aci_identity_key_pair.identity_key(),
                pni_identity_key_pair.identity_key(),
                dar,
            )
            .await?;

        Ok(result)
    }
}
