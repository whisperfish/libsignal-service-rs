use crate::push_service::{
    ConfirmCodeMessage, DeviceId, PushService, SmsVerificationCodeResponse,
    VoiceVerificationCodeResponse,
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

    pub async fn confirm_device(
        &mut self,
        confirmation_code: u32,
        confirm_code_message: &ConfirmCodeMessage,
    ) -> Result<DeviceId, Error> {
        Ok(self
            .service
            .confirm_device(confirmation_code, confirm_code_message)
            .await?)
    }
}
