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
        Self { service, context }
    }

    pub async fn request_sms_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_sms_verification_code(phone_number)
            .await?)
    }

    pub async fn request_voice_verification_code(
        &mut self,
        phone_number: &str,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_voice_verification_code(phone_number)
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
    pub async fn update_pre_key_bundle(
        &mut self,
        store_context: StoreContext,
        pre_keys_offset_id: u32,
        next_signed_pre_key_id: u32,
    ) -> Result<(), ServiceError> {
        let prekey_count = self.service.get_pre_key_status().await?.count;
        log::trace!("Remaining pre-keys on server: {}", prekey_count);

        if prekey_count >= PRE_KEY_MINIMUM {
            log::info!("Available keys sufficient");
            return Ok(());
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
        Ok(())
    }
}
