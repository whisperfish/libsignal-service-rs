use crate::push_service::{PushService, SmsVerificationCodeResponse};

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
}
