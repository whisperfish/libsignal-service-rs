use crate::{
    configuration::{Endpoint, ServiceCredentials},
    pre_keys::{PreKeyEntity, PreKeyState},
    proto::{ProvisionEnvelope, ProvisionMessage, ProvisioningVersion},
    provisioning::{ProvisioningCipher, ProvisioningError},
    push_service::{PushService, ServiceError},
};

use std::collections::HashMap;
use std::convert::TryFrom;
use std::time::SystemTime;

use libsignal_protocol::keys::PublicKey;
use libsignal_protocol::{Context, StoreContext};

pub struct AccountManager<Service> {
    context: Context,
    service: Service,
    profile_key: Option<Vec<u8>>,
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
        profile_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            context,
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
            .get_json(Endpoint::Service, "/v1/devices/provisioning/code", None)
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
                None,
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

        let provisioning_code = self.new_device_provisioning_code().await?;

        let msg = ProvisionMessage {
            identity_key_public: Some(
                identity_key_pair.public().to_bytes()?.as_slice().to_vec(),
            ),
            identity_key_private: Some(
                identity_key_pair.private().to_bytes()?.as_slice().to_vec(),
            ),
            number: Some(credentials.e164()),
            uuid: credentials.uuid.as_ref().map(|u| u.to_string()),
            profile_key: self.profile_key.clone(),
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
        self.send_provisioning_message(ephemeral_id, encrypted)
            .await?;
        Ok(())
    }
}
