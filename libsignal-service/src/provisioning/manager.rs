use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

use crate::{
    configuration::{Endpoint, ServiceConfiguration},
    messagepipe::ServiceCredentials,
    prelude::PushService,
    push_service::{DeviceCapabilities, DeviceId, ServiceError},
    utils::{serde_base64, serde_optional_base64},
    USER_AGENT,
};

/// Message received after confirming the SMS/voice code on registration.
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
/// Message received when linking a new secondary device.
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

#[derive(Clone)]
pub struct ProvisioningManager<P: PushService> {
    push_service: P,
    phone_number: PhoneNumber,
}

impl<P: PushService> ProvisioningManager<P> {
    pub fn new(
        cfg: impl Into<ServiceConfiguration>,
        phone_number: PhoneNumber,
        password: String,
    ) -> Self {
        Self {
            phone_number: phone_number.clone(),
            push_service: P::new(
                cfg,
                Some(ServiceCredentials {
                    phonenumber: phone_number,
                    password: Some(password),
                    uuid: None,
                    signaling_key: None,
                    device_id: None,
                }),
                USER_AGENT,
            ),
        }
    }

    pub async fn request_sms_verification_code(
        &mut self,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        let res = match self
            .push_service
            .get_json(
                Endpoint::Service,
                self.build_verification_code_request_url(
                    "sms", captcha, challenge,
                )
                .as_ref(),
                None,
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        };
        match res {
            Ok(_) => Ok(SmsVerificationCodeResponse::SmsSent),
            Err(ServiceError::UnhandledResponseCode { http_code: 402 }) => {
                Ok(SmsVerificationCodeResponse::CaptchaRequired)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn request_voice_verification_code(
        &mut self,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        let res = match self
            .push_service
            .get_json(
                Endpoint::Service,
                self.build_verification_code_request_url(
                    "voice", captcha, challenge,
                )
                .as_ref(),
                None,
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        };
        match res {
            Ok(_) => Ok(VoiceVerificationCodeResponse::CallIssued),
            Err(ServiceError::UnhandledResponseCode { http_code: 402 }) => {
                Ok(VoiceVerificationCodeResponse::CaptchaRequired)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn confirm_verification_code(
        &mut self,
        confirm_code: u32,
        confirm_verification_message: ConfirmCodeMessage,
    ) -> Result<ConfirmCodeResponse, ServiceError> {
        self.push_service
            .put_json(
                Endpoint::Service,
                &format!("/v1/accounts/code/{}", confirm_code),
                None,
                confirm_verification_message,
            )
            .await
    }

    pub async fn confirm_device(
        &mut self,
        confirm_code: u32,
        confirm_code_message: ConfirmDeviceMessage,
    ) -> Result<DeviceId, ServiceError> {
        self.push_service
            .put_json(
                Endpoint::Service,
                &format!("/v1/devices/{}", confirm_code),
                None,
                confirm_code_message,
            )
            .await
    }

    fn build_verification_code_request_url(
        &self,
        msg_type: &str,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> String {
        let phone_number =
            self.phone_number.format().mode(phonenumber::Mode::E164);
        if let Some(cl) = challenge {
            format!(
                "/v1/accounts/{}/code/{}?challenge={}",
                msg_type, phone_number, cl
            )
        } else if let Some(cc) = captcha {
            format!(
                "/v1/accounts/{}/code/{}?captcha={}",
                msg_type, phone_number, cc
            )
        } else {
            format!("/v1/accounts/{}/code/{}", msg_type, phone_number)
        }
    }
}
