use crate::{
    push_service::{PushService, SmsVerificationCodeResponse, VoiceVerificationCodeResponse},
    registration::{ConfirmCodeMessage, DeviceId},
};

use failure::Error;

pub struct AccountManager<Service> {
    service: Service,
}

impl<Service: PushService> AccountManager<Service> {
    pub fn new(service: Service) -> Self {
        Self { service }
    }

    pub async fn request_sms_verification_code(
        &mut self,
    ) -> Result<SmsVerificationCodeResponse, Error> {
        Ok(self.service.request_sms_verification_code().await?)
    }

    pub async fn request_voice_verification_code(
        &mut self,
    ) -> Result<VoiceVerificationCodeResponse, Error> {
        Ok(self.service.request_voice_verification_code().await?)
    }

    pub async fn confirm_registration(
        &mut self,
        confirm_code_message: &ConfirmCodeMessage,
    ) -> Result<DeviceId, Error> {
        Ok(self
            .service
            .confirm_registration(confirm_code_message)
            .await?)
    }
}
