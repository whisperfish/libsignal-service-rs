use base64::prelude::*;
use std::collections::HashMap;
use std::convert::TryInto;

use aes::cipher::{KeyIvInit, StreamCipher as _};
use hmac::digest::Output;
use hmac::{Hmac, Mac};
use libsignal_protocol::{
    IdentityKey, IdentityKeyStore, KeyPair, PrivateKey, PublicKey,
    SignalProtocolError,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing_futures::Instrument;
use zkgroup::profiles::ProfileKey;

use crate::pre_keys::{
    KyberPreKeyEntity, PreKeysStore, SignedPreKeyEntity, PRE_KEY_BATCH_SIZE,
    PRE_KEY_MINIMUM,
};
use crate::proto::DeviceName;
use crate::provisioning::generate_registration_id;
use crate::push_service::{AvatarWrite, RecaptchaAttributes, ServiceIdType};
use crate::sender::OutgoingPushMessage;
use crate::session_store::SessionStoreExt;
use crate::utils::BASE64_RELAXED;
use crate::ServiceAddress;
use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::PreKeyState,
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
    pub avatar: Option<String>,
}

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
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, protocol_store, csprng))]
    pub async fn update_pre_key_bundle<
        R: rand::Rng + rand::CryptoRng,
        P: PreKeysStore,
    >(
        &mut self,
        protocol_store: &mut P,
        service_id_type: ServiceIdType,
        csprng: &mut R,
        use_last_resort_key: bool,
    ) -> Result<(), ServiceError> {
        let prekey_status = match self
            .service
            .get_pre_key_status(service_id_type)
            .instrument(tracing::span!(
                tracing::Level::DEBUG,
                "Fetching pre key status"
            ))
            .await
        {
            Ok(status) => status,
            Err(ServiceError::Unauthorized) => {
                tracing::info!("Got Unauthorized when fetching pre-key status. Assuming first installment.");
                // Additionally, the second PUT request will fail if this really comes down to an
                // authorization failure.
                crate::push_service::PreKeyStatus {
                    count: 0,
                    pq_count: 0,
                }
            },
            Err(e) => return Err(e),
        };
        tracing::trace!("Remaining pre-keys on server: {:?}", prekey_status);

        if prekey_status.count >= PRE_KEY_MINIMUM
            && prekey_status.pq_count >= PRE_KEY_MINIMUM
        {
            tracing::info!("Available keys sufficient");
            return Ok(());
        }

        let identity_key_pair = protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get identity key pair"))
            .await?;

        let (pre_keys, signed_pre_key, pq_pre_keys, pq_last_resort_key) =
            crate::pre_keys::generate_pre_keys(
                protocol_store,
                &identity_key_pair,
                csprng,
                use_last_resort_key,
                PRE_KEY_BATCH_SIZE,
                PRE_KEY_BATCH_SIZE,
            )
            .await?;

        let identity_key =
            identity_key_pair.identity_key().public_key().clone();

        let pre_key_state = PreKeyState {
            pre_keys,
            signed_pre_key,
            identity_key,
            pq_pre_keys,
            pq_last_resort_key,
        };

        self.service
            .register_pre_keys(service_id_type, pre_key_state)
            .instrument(tracing::span!(
                tracing::Level::DEBUG,
                "Uploading pre keys"
            ))
            .await?;

        Ok(())
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
                    body: BASE64_RELAXED.encode(body),
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
        aci_identity_store: &dyn IdentityKeyStore,
        pni_identity_store: &dyn IdentityKeyStore,
        credentials: ServiceCredentials,
    ) -> Result<(), LinkError> {
        let query: HashMap<_, _> = url.query_pairs().collect();
        let ephemeral_id = query.get("uuid").ok_or(LinkError::InvalidUuid)?;
        let pub_key =
            query.get("pub_key").ok_or(LinkError::InvalidPublicKey)?;
        let pub_key = BASE64_RELAXED
            .decode(&**pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;
        let pub_key = PublicKey::deserialize(&pub_key)
            .map_err(|_e| LinkError::InvalidPublicKey)?;

        let aci_identity_key_pair =
            aci_identity_store.get_identity_key_pair().await?;
        let pni_identity_key_pair =
            pni_identity_store.get_identity_key_pair().await?;

        if credentials.aci.is_none() {
            tracing::warn!("No local ACI set");
        }
        if credentials.pni.is_none() {
            tracing::warn!("No local PNI set");
        }

        let provisioning_code = self.new_device_provisioning_code().await?;

        let msg = ProvisionMessage {
            aci: credentials.aci.as_ref().map(|u| u.to_string()),
            aci_identity_key_public: Some(
                aci_identity_key_pair.public_key().serialize().into_vec(),
            ),
            aci_identity_key_private: Some(
                aci_identity_key_pair.private_key().serialize(),
            ),
            number: Some(credentials.e164()),
            pni_identity_key_public: Some(
                pni_identity_key_pair.public_key().serialize().into_vec(),
            ),
            pni_identity_key_private: Some(
                pni_identity_key_pair.private_key().serialize(),
            ),
            pni: credentials.pni.as_ref().map(uuid::Uuid::to_string),
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
        public_key: &IdentityKey,
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

    /// Initialize PNI on linked devices.
    ///
    /// Should be called as the primary device to migrate from pre-PNI to PNI.
    ///
    /// This is the equivalent of Android's PnpInitializeDevicesJob or iOS' PniHelloWorldManager.
    pub async fn pnp_initialize_devices<
        R: rand::Rng + rand::CryptoRng,
        Aci: PreKeysStore + SessionStoreExt,
        Pni: PreKeysStore,
    >(
        &mut self,
        aci_protocol_store: &mut Aci,
        pni_protocol_store: &mut Pni,
        local_aci: ServiceAddress,
        csprng: &mut R,
    ) -> Result<(), ServiceError> {
        let pni_identity_key_pair =
            pni_protocol_store.get_identity_key_pair().await?;

        let pni_identity_key = pni_identity_key_pair.identity_key();

        // For every linked device, we generate a new set of pre-keys, and send them to the device.
        let local_device_ids = aci_protocol_store
            .get_sub_device_sessions(&local_aci)
            .await?;

        let mut device_messages =
            Vec::<OutgoingPushMessage>::with_capacity(local_device_ids.len());
        let mut device_pni_signed_prekeys =
            HashMap::<String, SignedPreKeyEntity>::with_capacity(
                local_device_ids.len(),
            );
        let mut device_pni_last_resort_kyber_prekeys =
            HashMap::<String, KyberPreKeyEntity>::with_capacity(
                local_device_ids.len(),
            );
        let mut pni_registration_ids =
            HashMap::<String, u32>::with_capacity(local_device_ids.len());

        let signature_valid_on_each_signed_pre_key = true;
        for local_device_id in
            std::iter::once(DEFAULT_DEVICE_ID).chain(local_device_ids)
        {
            let local_protocol_address =
                local_aci.to_protocol_address(local_device_id);
            let span = tracing::trace_span!(
                "filtering devices",
                address = %local_protocol_address
            );
            // Skip if we don't have a session with the device
            if (local_device_id != DEFAULT_DEVICE_ID)
                && aci_protocol_store
                    .load_session(&local_protocol_address)
                    .instrument(span)
                    .await?
                    .is_none()
            {
                tracing::warn!(
                    "No session with device {}, skipping PNI provisioning",
                    local_device_id
                );
                continue;
            }
            let (
                _pre_keys,
                signed_pre_key_entity,
                _kyber_pre_key_entities,
                last_resort_kyber_prekey,
            ) = crate::pre_keys::generate_pre_keys(
                pni_protocol_store,
                &pni_identity_key_pair,
                csprng,
                true,
                0,
                0,
            )
            .await?;
            let registration_id = generate_registration_id(csprng);

            let local_device_id_s = local_device_id.to_string();
            device_pni_signed_prekeys
                .insert(local_device_id_s.clone(), signed_pre_key_entity);
            device_pni_last_resort_kyber_prekeys.insert(
                local_device_id_s.clone(),
                last_resort_kyber_prekey.expect("requested last resort key"),
            );
            pni_registration_ids
                .insert(local_device_id_s.clone(), registration_id);

            assert!(_pre_keys.is_empty());
            assert!(_kyber_pre_key_entities.is_empty());
        }

        self.service
            .distribute_pni_keys(
                pni_identity_key,
                device_messages,
                device_pni_signed_prekeys,
                device_pni_last_resort_kyber_prekeys,
                pni_registration_ids,
                signature_valid_on_each_signed_pre_key,
            )
            .await?;

        Ok(())
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
    identity_public: &IdentityKey,
) -> Result<DeviceName, ServiceError> {
    let plaintext = device_name.as_bytes().to_vec();
    let ephemeral_key_pair = KeyPair::generate(csprng);

    let master_secret = ephemeral_key_pair
        .private_key
        .calculate_agreement(identity_public.public_key())?;

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
    use crate::utils::BASE64_RELAXED;
    use base64::Engine;
    use libsignal_protocol::{IdentityKeyPair, PrivateKey, PublicKey};

    use super::DeviceName;

    #[test]
    fn encrypt_device_name() -> anyhow::Result<()> {
        let input_device_name = "Nokia 3310 Millenial Edition";
        let mut csprng = rand::thread_rng();
        let identity = IdentityKeyPair::generate(&mut csprng);

        let device_name = super::encrypt_device_name(
            &mut csprng,
            input_device_name,
            &identity.identity_key(),
        )?;

        let decrypted_device_name =
            super::decrypt_device_name(&identity.private_key(), &device_name)?;

        assert_eq!(input_device_name, decrypted_device_name);

        Ok(())
    }

    #[test]
    fn decrypt_device_name() -> anyhow::Result<()> {
        let ephemeral_private_key = PrivateKey::deserialize(
            &BASE64_RELAXED
                .decode("0CgxHjwwblXjvX8sD5wZDWdYToMRf+CZSlgaUrxCGVo=")?,
        )?;
        let ephemeral_public_key = PublicKey::deserialize(
            &BASE64_RELAXED
                .decode("BcZS+Lt6yAKbEpXnRX+I5wHqesuvu93Q2V+fjidwW8R6")?,
        )?;

        let device_name = DeviceName {
            ephemeral_public: Some(ephemeral_public_key.serialize().to_vec()),
            synthetic_iv: Some(
                BASE64_RELAXED.decode("86gekHGmltnnZ9QARhiFcg==")?,
            ),
            ciphertext: Some(
                BASE64_RELAXED
                    .decode("MtJ9/9KBWLBVAxfZJD4pLKzP4q+iodRJeCc+/A==")?,
            ),
        };

        let decrypted_device_name =
            super::decrypt_device_name(&ephemeral_private_key, &device_name)?;

        assert_eq!(decrypted_device_name, "Nokia 3310 Millenial Edition");

        Ok(())
    }
}
