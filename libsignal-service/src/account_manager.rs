use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use aes::cipher::{KeyIvInit, StreamCipher as _};
use hmac::digest::Output;
use hmac::{Hmac, Mac};
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKeyStore, KeyPair, KyberPreKeyRecord,
    PreKeyRecord, PrivateKey, ProtocolStore, PublicKey, SignalProtocolError,
    SignedPreKeyRecord,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zkgroup::profiles::ProfileKey;

use crate::pre_keys::KyberPreKeyEntity;
use crate::proto::DeviceName;
use crate::push_service::{AvatarWrite, RecaptchaAttributes, ServiceIdType};
use crate::ServiceAddress;
use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::{PreKeyEntity, PreKeyState},
    profile_cipher::{ProfileCipher, ProfileCipherError},
    profile_name::ProfileName,
    proto::{ProvisionEnvelope, ProvisionMessage, ProvisioningVersion},
    provisioning::{ProvisioningCipher, ProvisioningError},
    push_service::{
        AccountAttributes, HttpAuthOverride, PushService, ServiceError,
    },
    utils::serde_base64,
};

type Aes256Ctr128BE = ctr::Ctr128BE<aes::Aes256>;

pub struct AccountManager<Service> {
    service: Service,
    profile_key: Option<ProfileKey>,
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

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub name: Option<ProfileName<String>>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
}

const PRE_KEY_MINIMUM: u32 = 10;
const PRE_KEY_BATCH_SIZE: u32 = 100;
const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;

impl<Service: PushService> AccountManager<Service> {
    pub fn new(service: Service, profile_key: Option<ProfileKey>) -> Self {
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
    /// Returns the next pre-key offset, pq pre-key offset, and next signed pre-key offset as a tuple.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_pre_key_bundle<
        R: rand::Rng + rand::CryptoRng,
        P: ProtocolStore,
    >(
        &mut self,
        protocol_store: &mut P,
        csprng: &mut R,
        pre_keys_offset_id: u32,
        next_signed_pre_key_id: u32,
        pq_pre_keys_offset_id: u32,
        use_last_resort_key: bool,
    ) -> Result<(u32, u32, u32), ServiceError> {
        let prekey_status = match self
            .service
            .get_pre_key_status(ServiceIdType::AccountIdentity)
            .await
        {
            Ok(status) => status,
            Err(ServiceError::Unauthorized) => {
                log::info!("Got Unauthorized when fetching pre-key status. Assuming first installment.");
                // Additionally, the second PUT request will fail if this really comes down to an
                // authorization failure.
                crate::push_service::PreKeyStatus {
                    count: 0,
                    pq_count: 0,
                }
            },
            Err(e) => return Err(e),
        };
        log::trace!("Remaining pre-keys on server: {:?}", prekey_status);

        if prekey_status.count >= PRE_KEY_MINIMUM
            && prekey_status.pq_count >= PRE_KEY_MINIMUM
        {
            log::info!("Available keys sufficient");
            return Ok((
                pre_keys_offset_id,
                pq_pre_keys_offset_id,
                next_signed_pre_key_id,
            ));
        }

        let identity_key_pair = protocol_store.get_identity_key_pair().await?;

        let mut pre_key_entities = vec![];
        let mut pq_pre_key_entities = vec![];

        // EC keys
        for i in 0..PRE_KEY_BATCH_SIZE {
            let key_pair = KeyPair::generate(csprng);
            let pre_key_id = (((pre_keys_offset_id + i)
                % (PRE_KEY_MEDIUM_MAX_VALUE - 1))
                + 1)
            .into();
            let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);
            protocol_store
                .save_pre_key(pre_key_id, &pre_key_record)
                .await?;
            // TODO: Shouldn't this also remove the previous pre-keys from storage?
            //       I think we might want to update the storage, and then sync the storage to the
            //       server.

            pre_key_entities.push(PreKeyEntity::try_from(pre_key_record)?);
        }

        // Kyber keys
        for i in 0..PRE_KEY_BATCH_SIZE {
            let pre_key_id = (((pq_pre_keys_offset_id + i)
                % (PRE_KEY_MEDIUM_MAX_VALUE - 1))
                + 1)
            .into();
            let pre_key_record = KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                pre_key_id,
                identity_key_pair.private_key(),
            )?;
            protocol_store
                .save_kyber_pre_key(pre_key_id, &pre_key_record)
                .await?;
            // TODO: Shouldn't this also remove the previous pre-keys from storage?
            //       I think we might want to update the storage, and then sync the storage to the
            //       server.

            pq_pre_key_entities
                .push(KyberPreKeyEntity::try_from(pre_key_record)?);
        }

        // Generate and store the next signed prekey
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signed_pre_key_public = signed_pre_key_pair.public_key;
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_public.serialize(), csprng)?;

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        let signed_prekey_record = SignedPreKeyRecord::new(
            next_signed_pre_key_id.into(),
            unix_time.as_millis() as u64,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        );

        protocol_store
            .save_signed_pre_key(
                next_signed_pre_key_id.into(),
                &signed_prekey_record,
            )
            .await?;

        let pre_key_state = PreKeyState {
            pre_keys: pre_key_entities,
            signed_pre_key: signed_prekey_record.try_into()?,
            identity_key: *identity_key_pair.public_key(),
            pq_pre_keys: pq_pre_key_entities,
            pq_last_resort_key: if use_last_resort_key {
                log::warn!("Last resort Kyber key unimplemented");
                // Note about the last-resort key:
                // mark_kyber_pre_key_used() should retain the last-resort key, but can safely
                // remove the ephemeral pre keys.  This implies that generating the last-resort key
                // should notify the pre-key store, when saving the key, that it concerns a
                // last-resort key.  I don't see how this can be communicated to the store, and I
                // fear that we need to reengineer the whole prekeystore system as a whole.
                None
                // Some(KyberPreKeyEntity {
                //     key_id: 0x7fffffff,
                //     public_key: "NDI=".into(),
                // })
            } else {
                None
            },
        };

        self.service
            .register_pre_keys(ServiceIdType::AccountIdentity, pre_key_state)
            .await?;

        log::trace!("Successfully refreshed prekeys");
        Ok((
            pre_keys_offset_id + PRE_KEY_BATCH_SIZE,
            pq_pre_keys_offset_id + PRE_KEY_BATCH_SIZE,
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
                &[],
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
        #[derive(serde::Serialize)]
        struct ProvisioningMessage {
            body: String,
        }

        let body = env.encode_to_vec();

        self.service
            .put_json(
                Endpoint::Service,
                &format!("/v1/provisioning/{}", destination),
                &[],
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

        let identity_key_pair = identity_store.get_identity_key_pair().await?;

        if credentials.uuid.is_none() {
            log::warn!("No local UUID set");
        }

        let provisioning_code = self.new_device_provisioning_code().await?;

        let msg = ProvisionMessage {
            aci: credentials.uuid.as_ref().map(|u| u.to_string()),
            aci_identity_key_public: Some(
                identity_key_pair.public_key().serialize().into_vec(),
            ),
            aci_identity_key_private: Some(
                identity_key_pair.private_key().serialize(),
            ),
            number: Some(credentials.e164()),
            // TODO: implement pni fields
            pni_identity_key_public: None,
            pni_identity_key_private: None,
            pni: None,
            profile_key: self.profile_key.as_ref().map(|x| x.bytes.to_vec()),
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
    /// manager.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _>(uuid, name, about, about_emoji, _)
    /// ```
    /// in which the `retain_avatar` parameter sets whether to remove (`false`) or retain (`true`) the
    /// currently set avatar.
    pub async fn upload_versioned_profile_without_avatar<S: AsRef<str>>(
        &mut self,
        aci: libsignal_protocol::Aci,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
        retain_avatar: bool,
    ) -> Result<(), ProfileManagerError> {
        self.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _>(
            aci,
            name,
            about,
            about_emoji,
            if retain_avatar {
                AvatarWrite::RetainAvatar
            } else {
                AvatarWrite::NoAvatar
            },
        )
        .await?;
        Ok(())
    }

    pub async fn retrieve_profile(
        &mut self,
        address: ServiceAddress,
    ) -> Result<Profile, ProfileManagerError> {
        let profile_key =
            self.profile_key.expect("set profile key in AccountManager");

        let encrypted_profile = self
            .service
            .retrieve_profile_by_id(address, Some(profile_key))
            .await?;

        let profile_cipher = ProfileCipher::from(profile_key);
        Ok(encrypted_profile.decrypt(profile_cipher)?)
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
        aci: libsignal_protocol::Aci,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
        avatar: AvatarWrite<&'s mut C>,
    ) -> Result<Option<String>, ProfileManagerError> {
        let profile_key =
            self.profile_key.expect("set profile key in AccountManager");
        let profile_cipher = ProfileCipher::from(profile_key);

        // Profile encryption
        let name = profile_cipher.encrypt_name(name.as_ref())?;
        let about = about.unwrap_or_default();
        let about = profile_cipher.encrypt_about(about)?;
        let about_emoji = about_emoji.unwrap_or_default();
        let about_emoji = profile_cipher.encrypt_emoji(about_emoji)?;

        // If avatar -> upload
        if matches!(avatar, AvatarWrite::NewAvatar(_)) {
            // FIXME ProfileCipherOutputStream.java
            // It's just AES GCM, but a bit of work to decently implement it with a stream.
            unimplemented!("Setting avatar requires ProfileCipherStream")
        }

        let profile_key = profile_cipher.into_inner();
        let commitment = profile_key.get_commitment(aci);
        let profile_key_version = profile_key.get_profile_key_version(aci);

        Ok(self
            .service
            .write_profile::<C, S>(
                &profile_key_version,
                &name,
                &about,
                &about_emoji,
                &commitment,
                avatar,
            )
            .await?)
    }

    /// Set profile attributes
    ///
    /// Signal Android does not allow unsetting voice/video.
    pub async fn set_account_attributes(
        &mut self,
        attributes: AccountAttributes,
    ) -> Result<(), ServiceError> {
        self.service.set_account_attributes(attributes).await
    }

    /// Update (encrypted) device name
    pub async fn update_device_name(
        &mut self,
        device_name: &str,
        public_key: &PublicKey,
    ) -> Result<(), ServiceError> {
        let encrypted_device_name = encrypt_device_name(
            &mut rand::thread_rng(),
            device_name,
            public_key,
        )?;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Data {
            #[serde(with = "serde_base64")]
            device_name: Vec<u8>,
        }

        self.service
            .put_json(
                Endpoint::Service,
                "/v1/accounts/name",
                &[],
                HttpAuthOverride::NoOverride,
                Data {
                    device_name: encrypted_device_name.encode_to_vec(),
                },
            )
            .await?;

        Ok(())
    }

    /// Upload a proof-required reCaptcha token and response.
    ///
    /// Token gotten originally with HTTP status 428 response to sending a message.
    /// Captcha gotten from user completing the challenge captcha.
    ///
    /// It's either a silent OK, or throws a ServiceError.
    pub async fn submit_recaptcha_challenge(
        &mut self,
        token: &str,
        captcha: &str,
    ) -> Result<(), ServiceError> {
        let payload = RecaptchaAttributes {
            r#type: String::from("recaptcha"),
            token: String::from(token),
            captcha: String::from(captcha),
        };
        self.service
            .put_json(
                Endpoint::Service,
                "/v1/challenge",
                &[],
                HttpAuthOverride::NoOverride,
                payload,
            )
            .await
    }
}

fn calculate_hmac256(
    mac_key: &[u8],
    ciphertext: &[u8],
) -> Result<Output<Hmac<Sha256>>, ServiceError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|_| ServiceError::MacError)?;
    mac.update(ciphertext);
    Ok(mac.finalize().into_bytes())
}

pub fn encrypt_device_name<R: rand::Rng + rand::CryptoRng>(
    csprng: &mut R,
    device_name: &str,
    identity_public: &PublicKey,
) -> Result<DeviceName, ServiceError> {
    let plaintext = device_name.as_bytes().to_vec();
    let ephemeral_key_pair = KeyPair::generate(csprng);

    let master_secret = ephemeral_key_pair
        .private_key
        .calculate_agreement(identity_public)?;

    let key1 = calculate_hmac256(&master_secret, b"auth")?;
    let synthetic_iv = calculate_hmac256(&key1, &plaintext)?;
    let synthetic_iv = &synthetic_iv[..16];

    let key2 = calculate_hmac256(&master_secret, b"cipher")?;
    let cipher_key = calculate_hmac256(&key2, synthetic_iv)?;

    let mut ciphertext = plaintext;

    const IV: [u8; 16] = [0; 16];
    let mut cipher = Aes256Ctr128BE::new(&cipher_key, &IV.into());
    cipher.apply_keystream(&mut ciphertext);

    let device_name = DeviceName {
        ephemeral_public: Some(
            ephemeral_key_pair.public_key.serialize().to_vec(),
        ),
        synthetic_iv: Some(synthetic_iv.to_vec()),
        ciphertext: Some(ciphertext),
    };

    Ok(device_name)
}

pub fn decrypt_device_name(
    private_key: &PrivateKey,
    device_name: &DeviceName,
) -> Result<String, ServiceError> {
    let DeviceName {
        ephemeral_public: Some(ephemeral_public),
        synthetic_iv: Some(synthetic_iv),
        ciphertext: Some(ciphertext),
    } = device_name
    else {
        return Err(ServiceError::InvalidDeviceName);
    };

    let synthetic_iv: [u8; 16] = synthetic_iv[..synthetic_iv.len().min(16)]
        .try_into()
        .map_err(|_| ServiceError::MacError)?;

    let ephemeral_public = PublicKey::deserialize(ephemeral_public)?;

    let master_secret = private_key.calculate_agreement(&ephemeral_public)?;
    let key2 = calculate_hmac256(&master_secret, b"cipher")?;
    let cipher_key = calculate_hmac256(&key2, &synthetic_iv)?;

    let mut plaintext = ciphertext.to_vec();
    const IV: [u8; 16] = [0; 16];
    let mut cipher =
        Aes256Ctr128BE::new(cipher_key.as_slice().into(), &IV.into());
    cipher.apply_keystream(&mut plaintext);

    let key1 = calculate_hmac256(&master_secret, b"auth")?;
    let our_synthetic_iv = calculate_hmac256(&key1, &plaintext)?;
    let our_synthetic_iv = &our_synthetic_iv[..16];

    if synthetic_iv != our_synthetic_iv {
        Err(ServiceError::MacError)
    } else {
        Ok(String::from_utf8_lossy(&plaintext).to_string())
    }
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::{KeyPair, PrivateKey, PublicKey};

    use super::DeviceName;

    #[test]
    fn encrypt_device_name() -> anyhow::Result<()> {
        let input_device_name = "Nokia 3310 Millenial Edition";
        let mut csprng = rand::thread_rng();
        let identity = KeyPair::generate(&mut csprng);

        let device_name = super::encrypt_device_name(
            &mut csprng,
            input_device_name,
            &identity.public_key,
        )?;

        let decrypted_device_name =
            super::decrypt_device_name(&identity.private_key, &device_name)?;

        assert_eq!(input_device_name, decrypted_device_name);

        Ok(())
    }

    #[test]
    fn decrypt_device_name() -> anyhow::Result<()> {
        let ephemeral_private_key = PrivateKey::deserialize(&base64::decode(
            "0CgxHjwwblXjvX8sD5wZDWdYToMRf+CZSlgaUrxCGVo=",
        )?)?;
        let ephemeral_public_key = PublicKey::deserialize(&base64::decode(
            "BcZS+Lt6yAKbEpXnRX+I5wHqesuvu93Q2V+fjidwW8R6",
        )?)?;

        let device_name = DeviceName {
            ephemeral_public: Some(ephemeral_public_key.serialize().to_vec()),
            synthetic_iv: Some(base64::decode("86gekHGmltnnZ9QARhiFcg==")?),
            ciphertext: Some(base64::decode(
                "MtJ9/9KBWLBVAxfZJD4pLKzP4q+iodRJeCc+/A==",
            )?),
        };

        let decrypted_device_name =
            super::decrypt_device_name(&ephemeral_private_key, &device_name)?;

        assert_eq!(decrypted_device_name, "Nokia 3310 Millenial Edition");

        Ok(())
    }
}
