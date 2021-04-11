use crate::configuration::ServiceCredentials;
use crate::pre_keys::{PreKeyEntity, PreKeyState};
use crate::profile_cipher::{ProfileCipher, ProfileCipherError};
use crate::profile_name::ProfileName;
use crate::provisioning::*;
use crate::push_service::{
    ConfirmDeviceMessage, DeviceId, PushService, ServiceError,
    SmsVerificationCodeResponse, VoiceVerificationCodeResponse,
};

use std::collections::HashMap;
use std::convert::TryFrom;
use std::time::SystemTime;

use libsignal_protocol::keys::PublicKey;
use libsignal_protocol::{Context, StoreContext};

use phonenumber::PhoneNumber;

use zkgroup::profiles::ProfileKey;

pub struct AccountManager<Service> {
    context: Context,
    service: Service,
    profile_key: Option<[u8; 32]>,
}

#[derive(thiserror::Error, Debug)]
pub enum ProfileManagerError {
    #[error(transparent)]
    ServiceError(#[from] ServiceError),
    #[error(transparent)]
    ProfileCipherError(#[from] ProfileCipherError),
}

#[derive(thiserror::Error, Debug)]
pub enum LinkError {
    #[error(transparent)]
    ServiceError(#[from] ServiceError),
    #[error("TsUrl has an invalid UUID field")]
    InvalidUuid,
    #[error("TsUrl has an invalid pub_key field")]
    InvalidPublicKey,
    #[error("Protocol error {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),
    #[error(transparent)]
    ProvisioningError(#[from] ProvisioningError),
}

const PRE_KEY_MINIMUM: u32 = 10;
const PRE_KEY_BATCH_SIZE: u32 = 100;

impl<Service: PushService> AccountManager<Service> {
    pub fn new(
        context: Context,
        service: Service,
        profile_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            context,
            service,
            profile_key,
        }
    }

    pub async fn request_sms_verification_code(
        &mut self,
        phone_number: PhoneNumber,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<SmsVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_sms_verification_code(phone_number, captcha, challenge)
            .await?)
    }

    pub async fn request_voice_verification_code(
        &mut self,
        phone_number: PhoneNumber,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<VoiceVerificationCodeResponse, ServiceError> {
        Ok(self
            .service
            .request_voice_verification_code(phone_number, captcha, challenge)
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
        use_last_resort_key: bool,
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
            last_resort_key: if use_last_resort_key {
                Some(PreKeyEntity {
                    key_id: 0x7fffffff,
                    public_key: "NDI=".into(),
                })
            } else {
                None
            },
        };

        self.service.register_pre_keys(pre_key_state).await?;

        log::trace!("Successfully refreshed prekeys");
        Ok((
            pre_keys_offset_id + PRE_KEY_BATCH_SIZE,
            next_signed_pre_key_id + 1,
        ))
    }

    /// Link a new device, given a tsurl.
    ///
    /// Equivalent of Java's `AccountManager::addDevice()`
    ///
    /// When calling this, make sure that UnidentifiedDelivery is disabled, ie., that your
    /// application does not send any unidentified messages before linking is complete.
    /// Cfr.:
    /// - `app/src/main/java/org/thoughtcrime/securesms/migrations/LegacyMigrationJob.java`:250 and;
    /// - `app/src/main/java/org/thoughtcrime/securesms/DeviceActivity.java`:195
    ///
    /// ```java
    /// TextSecurePreferences.setIsUnidentifiedDeliveryEnabled(context, false);
    /// ```
    pub async fn link_device(
        &mut self,
        url: url::Url,
        store_context: StoreContext,
        credentials: ServiceCredentials,
    ) -> Result<(), LinkError> {
        let query: HashMap<_, _> = url.query_pairs().collect();
        let ephemeral_id = query.get("uuid").ok_or(LinkError::InvalidUuid)?;
        let pub_key =
            query.get("pub_key").ok_or(LinkError::InvalidPublicKey)?;
        let pub_key = base64::decode(&**pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;
        let pub_key = PublicKey::decode_point(&self.context, &pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;

        let identity_key_pair = store_context.identity_key_pair()?;

        if credentials.uuid.is_none() {
            log::warn!("No local UUID set");
        }

        let provisioning_code =
            self.service.new_device_provisioning_code().await?;

        let msg = ProvisionMessage {
            identity_key_public: Some(
                identity_key_pair.public().to_bytes()?.as_slice().to_vec(),
            ),
            identity_key_private: Some(
                identity_key_pair.private().to_bytes()?.as_slice().to_vec(),
            ),
            number: Some(credentials.e164()),
            uuid: credentials.uuid.as_ref().map(|u| u.to_string()),
            profile_key: self.profile_key.as_ref().map(|x| x.to_vec()),
            // CURRENT is not exposed by prost :(
            provisioning_version: Some(i32::from(
                ProvisioningVersion::TabletSupport,
            ) as _),
            provisioning_code: Some(provisioning_code),
            read_receipts: None,
            user_agent: None,
        };

        let cipher =
            ProvisioningCipher::from_public(self.context.clone(), pub_key);

        let encrypted = cipher.encrypt(msg)?;
        self.service
            .send_provisioning_message(ephemeral_id, encrypted)
            .await?;
        Ok(())
    }

    /// Upload a profile
    ///
    /// Panics if no `profile_key` was set.
    ///
    /// Convenience method for
    /// ```ignore
    /// manager.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _>(uuid, name, about, about_emoji, None)
    /// ```
    pub async fn upload_versioned_profile_without_avatar<S: AsRef<str>>(
        &mut self,
        uuid: uuid::Uuid,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
    ) -> Result<(), ProfileManagerError> {
        self.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _>(
            uuid,
            name,
            about,
            about_emoji,
            None,
        )
        .await?;
        Ok(())
    }

    /// Upload a profile
    ///
    /// Panics if no `profile_key` was set.
    ///
    /// Returns the avatar url path.
    pub async fn upload_versioned_profile<
        's,
        C: std::io::Read + Send + 's,
        S: AsRef<str>,
    >(
        &mut self,
        uuid: uuid::Uuid,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
        avatar: Option<&'s mut C>,
    ) -> Result<Option<String>, ProfileManagerError> {
        let profile_key = self
            .profile_key
            .clone()
            .expect("set profile key in AccountManager");
        let profile_key = ProfileKey::create(profile_key);
        let profile_cipher = ProfileCipher::from(profile_key);

        // Profile encryption
        let name = profile_cipher.encrypt_name(name.as_ref())?;
        let about = about.unwrap_or_default();
        let about = profile_cipher.encrypt_about(about)?;
        let about_emoji = about_emoji.unwrap_or_default();
        let about_emoji = profile_cipher.encrypt_emoji(about_emoji)?;

        // If avatar -> upload
        if let Some(_avatar) = avatar {
            // FIXME ProfileCipherOutputStream.java
            // It's just AES GCM, but a bit of work to decently implement it with a stream.
            unimplemented!("Setting avatar requires ProfileCipherStream")
        }

        let profile_key = profile_cipher.into_inner();
        let commitment = profile_key.get_commitment(*uuid.as_bytes());
        let profile_key_version =
            profile_key.get_profile_key_version(*uuid.as_bytes());

        Ok(self
            .service
            .write_profile(
                &profile_key_version,
                &name,
                &about,
                &about_emoji,
                &commitment,
                None, // FIXME avatar
            )
            .await?)
    }
}
