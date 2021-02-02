use crate::pre_keys::{PreKeyEntity, PreKeyState};
use crate::push_service::{
    ConfirmDeviceMessage, DeviceId, PushService, ServiceError,
    SmsVerificationCodeResponse, VoiceVerificationCodeResponse,
};

use std::convert::TryFrom;
use std::time::SystemTime;

use libsignal_protocol::{Context, StoreContext};

pub struct AccountManager<Service> {
    context: Context,
    service: Service,
}

const PRE_KEY_MINIMUM: u32 = 10;
const PRE_KEY_BATCH_SIZE: u32 = 100;

impl<Service: PushService> AccountManager<Service> {
    pub fn new(context: Context, service: Service) -> Self {
        Self { context, service }
    }

    pub async fn request_sms_verification_code_with_data(
        &mut self,
        phone_number: &str,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_sms_verification_code(phone_number, captcha, challenge)
            .await?)
    }

    pub async fn request_sms_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_sms_verification_code(phone_number, None, None)
            .await?)
    }

    pub async fn request_voice_verification_code_with_data(
        &mut self,
        phone_number: &str,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_voice_verification_code(phone_number, captcha, challenge)
            .await?)
    }


    pub async fn request_voice_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_voice_verification_code(phone_number, None, None)
            .await?)
    }

    pub async fn confirm_device(
        &mut self,
        confirmation_code: u32,
        confirm_device_message: ConfirmDeviceMessage,
    ) -> Result<DeviceId, ServiceError> {
        Ok(self
            .service
            .confirm_device(confirmation_code, confirm_device_message)
            .await?)
    }

    /// Checks the availability of pre-keys, and updates them as necessary.
    ///
    /// Parameters are the protocol's `StoreContext`, and the offsets for the next pre-key and
    /// signed pre-keys.
    ///
    /// Equivalent to Java's RefreshPreKeysJob
    ///
    /// Returns the next pre-key offset and next signed pre-key offset as a tuple.
    pub async fn update_pre_key_bundle(
        &mut self,
        store_context: StoreContext,
        pre_keys_offset_id: u32,
        next_signed_pre_key_id: u32,
    ) -> Result<(u32, u32), ServiceError> {
        let prekey_count = match self.service.get_pre_key_status().await {
            Ok(status) => status.count,
            Err(ServiceError::Unauthorized) => {
                log::info!("Got Unauthorized when fetching pre-key status. Assuming first installment.");
                // Additionally, the second PUT request will fail if this really comes down to an
                // authorization failure.
                0
            }
            Err(e) => return Err(e),
        };
        log::trace!("Remaining pre-keys on server: {}", prekey_count);

        if prekey_count >= PRE_KEY_MINIMUM {
            log::info!("Available keys sufficient");
            return Ok((pre_keys_offset_id, next_signed_pre_key_id));
        }

        let pre_keys = libsignal_protocol::generate_pre_keys(
            &self.context,
            pre_keys_offset_id,
            PRE_KEY_BATCH_SIZE,
        )?;
        let identity_key_pair = store_context.identity_key_pair()?;
        let signed_pre_key = libsignal_protocol::generate_signed_pre_key(
            &self.context,
            &identity_key_pair,
            next_signed_pre_key_id,
            SystemTime::now(),
        )?;

        store_context.store_signed_pre_key(&signed_pre_key)?;

        let mut pre_key_entities = vec![];
        for pre_key in pre_keys {
            store_context.store_pre_key(&pre_key)?;
            pre_key_entities.push(PreKeyEntity::try_from(pre_key)?);
        }

        let pre_key_state = PreKeyState {
            pre_keys: pre_key_entities,
            signed_pre_key: signed_pre_key.into(),
            identity_key: identity_key_pair.public(),
        };

        self.service.register_pre_keys(pre_key_state).await?;

        log::trace!("Successfully refreshed prekeys");
        Ok((
            pre_keys_offset_id + PRE_KEY_BATCH_SIZE,
            next_signed_pre_key_id + 1,
        ))
    }
}
