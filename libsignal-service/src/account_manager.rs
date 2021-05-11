use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use libsignal_protocol::{
    IdentityKeyStore, KeyPair, PreKeyRecord, PreKeyStore, PublicKey,
    SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore,
};
use zkgroup::profiles::ProfileKey;

use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::{PreKeyEntity, PreKeyState},
    profile_cipher::{ProfileCipher, ProfileCipherError},
    profile_name::ProfileName,
    proto::{ProvisionEnvelope, ProvisionMessage, ProvisioningVersion},
    provisioning::{ProvisioningCipher, ProvisioningError},
    push_service::{
        AccountAttributes, DeviceCapabilities, HttpAuthOverride, PushService,
        ServiceError,
    },
};

pub struct AccountManager<Service> {
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
    ProtocolError(#[from] SignalProtocolError),
    #[error(transparent)]
    ProvisioningError(#[from] ProvisioningError),
}

#[derive(Debug, Default)]
pub struct Profile {
    pub name: Option<ProfileName<String>>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
}

const PRE_KEY_MINIMUM: u32 = 10;
const PRE_KEY_BATCH_SIZE: u32 = 100;
const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;

impl<Service: PushService> AccountManager<Service> {
    pub fn new(service: Service, profile_key: Option<[u8; 32]>) -> Self {
        Self {
            service,
            profile_key,
        }
    }

    /// Checks the availability of pre-keys, and updates them as necessary.
    ///
    /// Parameters are the protocol's `StoreContext`, and the offsets for the next pre-key and
    /// signed pre-keys.
    ///
    /// Equivalent to Java's RefreshPreKeysJob
    ///
    /// Returns the next pre-key offset and next signed pre-key offset as a tuple.
    #[allow(clippy::clippy::too_many_arguments)]
    pub async fn update_pre_key_bundle<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        identity_store: &dyn IdentityKeyStore,
        pre_key_store: &mut dyn PreKeyStore,
        signed_pre_key_store: &mut dyn SignedPreKeyStore,
        csprng: &mut R,
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

        let mut pre_key_entities = vec![];
        for i in 0..PRE_KEY_BATCH_SIZE {
            let key_pair = KeyPair::generate(csprng);
            let pre_key_id =
                ((pre_keys_offset_id + i) % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1;
            let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);
            pre_key_store
                .save_pre_key(pre_key_id, &pre_key_record, None)
                .await?;

            pre_key_entities.push(PreKeyEntity::try_from(pre_key_record)?);
        }

        // Generate and store the next signed prekey
        let identity_key_pair =
            identity_store.get_identity_key_pair(None).await?;
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signed_pre_key_public = signed_pre_key_pair.public_key;
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public.serialize(), csprng)?;

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let signed_prekey_record = SignedPreKeyRecord::new(
            next_signed_pre_key_id,
            unix_time.as_millis() as u64,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        );

        signed_pre_key_store
            .save_signed_pre_key(
                next_signed_pre_key_id,
                &signed_prekey_record,
                None,
            )
            .await?;

        let pre_key_state = PreKeyState {
            pre_keys: pre_key_entities,
            signed_pre_key: signed_prekey_record.try_into()?,
            identity_key: *identity_key_pair.public_key(),
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

    async fn new_device_provisioning_code(
        &mut self,
    ) -> Result<String, ServiceError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct DeviceCode {
            verification_code: String,
        }

        let dc: DeviceCode = self
            .service
            .get_json(
                Endpoint::Service,
                "/v1/devices/provisioning/code",
                HttpAuthOverride::NoOverride,
            )
            .await?;
        Ok(dc.verification_code)
    }

    async fn send_provisioning_message(
        &mut self,
        destination: &str,
        env: ProvisionEnvelope,
    ) -> Result<(), ServiceError> {
        use prost::Message;

        #[derive(serde::Serialize)]
        struct ProvisioningMessage {
            body: String,
        }

        let mut body = Vec::with_capacity(env.encoded_len());
        env.encode(&mut body).expect("infallible encode");

        self.service
            .put_json(
                Endpoint::Service,
                &format!("/v1/provisioning/{}", destination),
                HttpAuthOverride::NoOverride,
                &ProvisioningMessage {
                    body: base64::encode(body),
                },
            )
            .await
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
        identity_store: &dyn IdentityKeyStore,
        credentials: ServiceCredentials,
    ) -> Result<(), LinkError> {
        let query: HashMap<_, _> = url.query_pairs().collect();
        let ephemeral_id = query.get("uuid").ok_or(LinkError::InvalidUuid)?;
        let pub_key =
            query.get("pub_key").ok_or(LinkError::InvalidPublicKey)?;
        let pub_key = base64::decode(&**pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;
        let pub_key = PublicKey::deserialize(&pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;

        let identity_key_pair =
            identity_store.get_identity_key_pair(None).await?;

        if credentials.uuid.is_none() {
            log::warn!("No local UUID set");
        }

        let provisioning_code = self.new_device_provisioning_code().await?;

        let msg = ProvisionMessage {
            identity_key_public: Some(
                identity_key_pair.public_key().serialize().into_vec(),
            ),
            identity_key_private: Some(
                identity_key_pair.private_key().serialize(),
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

        let cipher = ProvisioningCipher::from_public(pub_key);

        let encrypted = cipher.encrypt(msg)?;
        self.send_provisioning_message(ephemeral_id, encrypted)
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

    pub async fn retrieve_profile(
        &mut self,
        uuid: uuid::Uuid,
    ) -> Result<Profile, ProfileManagerError> {
        let profile_key =
            self.profile_key.expect("set profile key in AccountManager");
        let profile_key = ProfileKey::create(profile_key);
        let profile_cipher = ProfileCipher::from(profile_key);

        let encrypted_profile = self
            .service
            .retrieve_profile_by_id(&uuid.to_string())
            .await?;

        // Profile decryption
        let name = encrypted_profile
            .name
            .map(|data| profile_cipher.decrypt_name(data))
            .transpose()?
            .flatten();
        let about = encrypted_profile
            .about
            .map(|data| profile_cipher.decrypt_about(data))
            .transpose()?;
        let about_emoji = encrypted_profile
            .about_emoji
            .map(|data| profile_cipher.decrypt_emoji(data))
            .transpose()?;

        Ok(Profile {
            name,
            about,
            about_emoji,
        })
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

    /// Set profile attributes
    ///
    /// Signal Android does not allow unsetting voice/video.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_account_attributes(
        &mut self,
        signaling_key: Option<Vec<u8>>,
        registration_id: u32,
        voice: bool,
        video: bool,
        fetches_messages: bool,
        pin: Option<String>,
        registration_lock: Option<String>,
        unidentified_access_key: Option<Vec<u8>>,
        unrestricted_unidentified_access: bool,
        discoverable_by_phone_number: bool,
        capabilities: DeviceCapabilities,
    ) -> Result<(), ServiceError> {
        let attribs = AccountAttributes {
            signaling_key,
            registration_id,
            voice,
            video,
            fetches_messages,
            pin,
            registration_lock,
            unidentified_access_key,
            unrestricted_unidentified_access,
            discoverable_by_phone_number,
            capabilities,
        };
        self.service.set_account_attributes(attribs).await?;
        Ok(())
    }
}
