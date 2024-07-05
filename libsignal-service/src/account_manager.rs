use base64::prelude::*;
use phonenumber::PhoneNumber;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};

use aes::cipher::{KeyIvInit, StreamCipher as _};
use hmac::digest::Output;
use hmac::{Hmac, Mac};
use libsignal_protocol::{
    kem, GenericSignedPreKey, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KeyPair, KyberPreKeyRecord, PrivateKey, ProtocolStore, PublicKey,
    SenderKeyStore, SignedPreKeyRecord, Timestamp,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing_futures::Instrument;
use zkgroup::profiles::ProfileKey;

use crate::content::ContentBody;
use crate::pre_keys::{
    KyberPreKeyEntity, PreKeyEntity, PreKeysStore, SignedPreKeyEntity,
    PRE_KEY_BATCH_SIZE, PRE_KEY_MINIMUM,
};
use crate::prelude::{MessageSender, MessageSenderError};
use crate::proto::sync_message::PniChangeNumber;
use crate::proto::{DeviceName, SyncMessage};
use crate::provisioning::generate_registration_id;
use crate::push_service::{
    AvatarWrite, DeviceActivationRequest, DeviceInfo, RecaptchaAttributes,
    RegistrationMethod, ServiceIdType, VerifyAccountResponse,
    DEFAULT_DEVICE_ID,
};
use crate::sender::OutgoingPushMessage;
use crate::session_store::SessionStoreExt;
use crate::timestamp::TimestampExt as _;
use crate::utils::{random_length_padding, BASE64_RELAXED};
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

        // XXX We should honestly compare the pre-key count with the number of pre-keys we have
        // locally. If we have more than the server, we should upload them.
        // Currently the trait doesn't allow us to do that, so we just upload the batch size and
        // pray.
        if prekey_status.count >= PRE_KEY_MINIMUM
            && prekey_status.pq_count >= PRE_KEY_MINIMUM
        {
            if protocol_store.signed_pre_keys_count().await? > 0
                && protocol_store.kyber_pre_keys_count(true).await? > 0
            {
                tracing::debug!("Available keys sufficient");
                return Ok(());
            }
            tracing::info!("Available keys sufficient; forcing refresh.");
        }

        let identity_key_pair = protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get identity key pair"))
            .await?;

        let last_resort_keys = protocol_store
            .load_last_resort_kyber_pre_keys()
            .instrument(tracing::trace_span!("fetch last resort key"))
            .await?;

        // XXX: Maybe this check should be done in the generate_pre_keys function?
        let has_last_resort_key = !last_resort_keys.is_empty();

        let (pre_keys, signed_pre_key, pq_pre_keys, pq_last_resort_key) =
            crate::pre_keys::replenish_pre_keys(
                protocol_store,
                &identity_key_pair,
                csprng,
                use_last_resort_key && !has_last_resort_key,
                PRE_KEY_BATCH_SIZE,
                PRE_KEY_BATCH_SIZE,
            )
            .await?;

        let pq_last_resort_key = if has_last_resort_key {
            if last_resort_keys.len() > 1 {
                tracing::warn!(
                    "More than one last resort key found; only uploading first"
                );
            }
            Some(KyberPreKeyEntity::try_from(last_resort_keys[0].clone())?)
        } else {
            pq_last_resort_key
                .map(KyberPreKeyEntity::try_from)
                .transpose()?
        };

        let identity_key = *identity_key_pair.identity_key();

        let pre_keys: Vec<_> = pre_keys
            .into_iter()
            .map(PreKeyEntity::try_from)
            .collect::<Result<_, _>>()?;
        let signed_pre_key = signed_pre_key.try_into()?;
        let pq_pre_keys: Vec<_> = pq_pre_keys
            .into_iter()
            .map(KyberPreKeyEntity::try_from)
            .collect::<Result<_, _>>()?;

        tracing::info!(
            "Uploading pre-keys: {} one-time, {} PQ, {} PQ last resort",
            pre_keys.len(),
            pq_pre_keys.len(),
            if pq_last_resort_key.is_some() { 1 } else { 0 }
        );

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
    ) -> Result<(), ProvisioningError> {
        let query: HashMap<_, _> = url.query_pairs().collect();
        let ephemeral_id =
            query.get("uuid").ok_or(ProvisioningError::MissingUuid)?;
        let pub_key = query
            .get("pub_key")
            .ok_or(ProvisioningError::MissingPublicKey)?;
        let pub_key = BASE64_RELAXED
            .decode(&**pub_key)
            .map_err(|e| ProvisioningError::InvalidPublicKey(e.into()))?;
        let pub_key = PublicKey::deserialize(&pub_key)
            .map_err(|e| ProvisioningError::InvalidPublicKey(e.into()))?;

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
            master_key: None, // XXX
        };

        let cipher = ProvisioningCipher::from_public(pub_key);

        let encrypted = cipher.encrypt(msg)?;
        self.send_provisioning_message(ephemeral_id, encrypted)
            .await?;
        Ok(())
    }

    pub async fn linked_devices(
        &mut self,
        aci_identity_store: &dyn IdentityKeyStore,
    ) -> Result<Vec<DeviceInfo>, ServiceError> {
        let device_infos = self.service.devices().await?;
        let aci_identity_keypair =
            aci_identity_store.get_identity_key_pair().await?;

        device_infos
            .into_iter()
            .map(|i| {
                Ok(DeviceInfo {
                    id: i.id,
                    name: i
                        .name
                        .map(|s| {
                            decrypt_device_name_from_device_info(
                                &s,
                                &aci_identity_keypair,
                            )
                        })
                        .transpose()?,
                    created: i.created,
                    last_seen: i.last_seen,
                })
            })
            .collect()
    }

    pub async fn register_account<
        R: rand::Rng + rand::CryptoRng,
        Aci: PreKeysStore + IdentityKeyStore,
        Pni: PreKeysStore + IdentityKeyStore,
    >(
        &mut self,
        csprng: &mut R,
        registration_method: RegistrationMethod<'_>,
        account_attributes: AccountAttributes,
        aci_protocol_store: &mut Aci,
        pni_protocol_store: &mut Pni,
        skip_device_transfer: bool,
    ) -> Result<VerifyAccountResponse, ProvisioningError> {
        let aci_identity_key_pair = aci_protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get ACI identity key pair"))
            .await?;
        let pni_identity_key_pair = pni_protocol_store
            .get_identity_key_pair()
            .instrument(tracing::trace_span!("get PNI identity key pair"))
            .await?;

        let (
            _aci_pre_keys,
            aci_signed_pre_key,
            _aci_kyber_pre_keys,
            aci_last_resort_kyber_prekey,
        ) = crate::pre_keys::replenish_pre_keys(
            aci_protocol_store,
            &aci_identity_key_pair,
            csprng,
            true,
            0,
            0,
        )
        .await?;

        let (
            _pni_pre_keys,
            pni_signed_pre_key,
            _pni_kyber_pre_keys,
            pni_last_resort_kyber_prekey,
        ) = crate::pre_keys::replenish_pre_keys(
            pni_protocol_store,
            &pni_identity_key_pair,
            csprng,
            true,
            0,
            0,
        )
        .await?;

        let aci_identity_key = aci_identity_key_pair.identity_key();
        let pni_identity_key = pni_identity_key_pair.identity_key();

        let dar = DeviceActivationRequest {
            aci_signed_pre_key: aci_signed_pre_key.try_into()?,
            pni_signed_pre_key: pni_signed_pre_key.try_into()?,
            aci_pq_last_resort_pre_key: aci_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
            pni_pq_last_resort_pre_key: pni_last_resort_kyber_prekey
                .expect("requested last resort prekey")
                .try_into()?,
        };

        let result = self
            .service
            .submit_registration_request(
                registration_method,
                account_attributes,
                skip_device_transfer,
                aci_identity_key,
                pni_identity_key,
                dar,
            )
            .await?;

        Ok(result)
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
            .put_json::<(), _>(
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
        // XXX So many constraints here, all imposed by the MessageSender
        R: rand::Rng + rand::CryptoRng,
        Aci: PreKeysStore + SessionStoreExt,
        Pni: PreKeysStore,
        AciOrPni: ProtocolStore + SenderKeyStore + SessionStoreExt + Sync + Clone,
    >(
        &mut self,
        aci_protocol_store: &mut Aci,
        pni_protocol_store: &mut Pni,
        mut sender: MessageSender<Service, AciOrPni, R>,
        local_aci: ServiceAddress,
        e164: PhoneNumber,
        csprng: &mut R,
    ) -> Result<(), MessageSenderError> {
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
                signed_pre_key,
                _kyber_pre_keys,
                last_resort_kyber_prekey,
            ) = if local_device_id == DEFAULT_DEVICE_ID {
                crate::pre_keys::replenish_pre_keys(
                    pni_protocol_store,
                    &pni_identity_key_pair,
                    csprng,
                    true,
                    0,
                    0,
                )
                .await?
            } else {
                // Generate a signed prekey
                let signed_pre_key_pair = KeyPair::generate(csprng);
                let signed_pre_key_public = signed_pre_key_pair.public_key;
                let signed_pre_key_signature =
                    pni_identity_key_pair.private_key().calculate_signature(
                        &signed_pre_key_public.serialize(),
                        csprng,
                    )?;

                let signed_prekey_record = SignedPreKeyRecord::new(
                    csprng.gen_range::<u32, _>(0..0xFFFFFF).into(),
                    Timestamp::now(),
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                );

                // Generate a last-resort Kyber prekey
                let kyber_pre_key_record = KyberPreKeyRecord::generate(
                    kem::KeyType::Kyber1024,
                    csprng.gen_range::<u32, _>(0..0xFFFFFF).into(),
                    pni_identity_key_pair.private_key(),
                )?;
                (
                    vec![],
                    signed_prekey_record,
                    vec![],
                    Some(kyber_pre_key_record),
                )
            };

            let registration_id = if local_device_id == DEFAULT_DEVICE_ID {
                pni_protocol_store.get_local_registration_id().await?
            } else {
                loop {
                    let regid = generate_registration_id(csprng);
                    if !pni_registration_ids.iter().any(|(_k, v)| *v == regid) {
                        break regid;
                    }
                }
            };

            let local_device_id_s = local_device_id.to_string();
            device_pni_signed_prekeys.insert(
                local_device_id_s.clone(),
                SignedPreKeyEntity::try_from(&signed_pre_key)?,
            );
            device_pni_last_resort_kyber_prekeys.insert(
                local_device_id_s.clone(),
                KyberPreKeyEntity::try_from(
                    last_resort_kyber_prekey
                        .as_ref()
                        .expect("requested last resort key"),
                )?,
            );
            pni_registration_ids
                .insert(local_device_id_s.clone(), registration_id);

            assert!(_pre_keys.is_empty());
            assert!(_kyber_pre_keys.is_empty());

            if local_device_id == DEFAULT_DEVICE_ID {
                // This is the primary device
                // We don't need to send a message to the primary device
                continue;
            }
            // cfr. SignalServiceMessageSender::getEncryptedSyncPniInitializeDeviceMessage
            let msg = SyncMessage {
                pni_change_number: Some(PniChangeNumber {
                    identity_key_pair: Some(
                        pni_identity_key_pair.serialize().to_vec(),
                    ),
                    signed_pre_key: Some(signed_pre_key.serialize()?),
                    last_resort_kyber_pre_key: Some(
                        last_resort_kyber_prekey
                            .expect("requested last resort key")
                            .serialize()?,
                    ),
                    registration_id: Some(registration_id),
                    new_e164: Some(
                        e164.format().mode(phonenumber::Mode::E164).to_string(),
                    ),
                }),
                padding: Some(random_length_padding(csprng, 512)),
                ..SyncMessage::default()
            };
            let content: ContentBody = msg.into();
            let msg = sender
                .create_encrypted_message(
                    &local_aci,
                    None,
                    local_device_id.into(),
                    &content.into_proto().encode_to_vec(),
                )
                .await?;
            device_messages.push(msg);
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

fn decrypt_device_name_from_device_info(
    string: &str,
    aci: &IdentityKeyPair,
) -> Result<String, ServiceError> {
    let data = BASE64_RELAXED.decode(string)?;
    let name = DeviceName::decode(&*data)?;
    crate::decrypt_device_name(aci.private_key(), &name)
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
            identity.identity_key(),
        )?;

        let decrypted_device_name =
            super::decrypt_device_name(identity.private_key(), &device_name)?;

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
