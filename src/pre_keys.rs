use std::convert::TryFrom;

use crate::{
    timestamp::TimestampExt as _,
    utils::{serde_base64, serde_identity_key},
};
use async_trait::async_trait;
use libsignal_protocol::{
    error::SignalProtocolError, kem, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KeyPair, KyberPreKeyId,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyRecord, PreKeyStore,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

#[async_trait(?Send)]
/// Additional methods for the Kyber pre key store
///
/// Analogue of Android's ServiceKyberPreKeyStore
///
/// Deletion is split with libsignal: it calls
/// [`mark_kyber_pre_key_used`](KyberPreKeyStore::mark_kyber_pre_key_used) on
/// decrypt, which deletes a one-time key and, for the last-resort key, only
/// errors on a base key seen before. Keys that are never used are reaped here
/// instead — `delete_all_stale_one_time_kyber_pre_keys` for one-time keys,
/// `remove_kyber_pre_key` for superseded last-resort keys.
pub trait KyberPreKeyStoreExt: KyberPreKeyStore {
    /// Store the last-resort key, flagged as such.
    ///
    /// Plain [`save_kyber_pre_key`](KyberPreKeyStore::save_kyber_pre_key)
    /// stores one-time keys.
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError>;

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError>;

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError>;

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_stale_one_time_kyber_pre_keys(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count_to_keep: usize,
    ) -> Result<(), SignalProtocolError>;
}

#[async_trait(?Send)]
/// Additional methods for the signed pre key store
pub trait SignedPreKeyStoreExt: SignedPreKeyStore {
    async fn load_signed_pre_keys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecord>, SignalProtocolError>;

    async fn remove_signed_pre_key(
        &mut self,
        pre_key_id: SignedPreKeyId,
    ) -> Result<(), SignalProtocolError>;
}

/// Stores the ID of keys published ahead of time
///
/// <https://signal.org/docs/specifications/x3dh/>
///
/// ## Last-ID contract
///
/// The `last_*_id` getters return the id most recently issued, 0 meaning none
/// yet. Generation starts one past that (increment + `% PRE_KEY_MEDIUM_MAX_VALUE`
/// wrap, so ids are 1-based), and the `set_last_*` setters record the last id
/// of the batch. Implementors MUST treat the setters as plain persistence:
/// write the value, return. They MUST NOT advance, wrap, or otherwise mutate
/// the id.
///
/// ## Active-ID contract
///
/// `set_active_*` records the id the server has accepted. The
/// `store_*_pre_key_bundle` methods do NOT set them; call
/// `mark_signed_pre_keys_active` only after a successful upload, so
/// `clean_stale_pre_keys` excludes the correct live key. The matching getters
/// return `None` before the first upload.
#[async_trait(?Send)]
pub trait PreKeysStore:
    PreKeyStore
    + IdentityKeyStore
    + SignedPreKeyStore
    + SignedPreKeyStoreExt
    + KyberPreKeyStore
    + KyberPreKeyStoreExt
{
    // ---- Last-ID getters ----

    /// ID of the most recently issued pre key, or 0 if there is none
    async fn last_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the most recently issued signed pre key, or 0 if there is none
    async fn last_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the most recently issued PQ pre key, or 0 if there is none
    async fn last_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    // ---- Last-ID setters (persistence only; do NOT advance) ----

    async fn set_last_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    async fn set_last_signed_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    async fn set_last_pq_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self)
        -> Result<usize, SignalProtocolError>;

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(
        &self,
        last_resort: bool,
    ) -> Result<usize, SignalProtocolError>;

    // ---- Active-ID getters ----

    async fn active_signed_prekey_id(
        &self,
    ) -> Result<Option<SignedPreKeyId>, SignalProtocolError>;

    async fn active_last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError>;

    // ---- Active-ID setters (call after successful server upload) ----

    async fn set_active_signed_prekey_id(
        &mut self,
        id: SignedPreKeyId,
    ) -> Result<(), SignalProtocolError>;

    async fn set_active_last_resort_kyber_prekey_id(
        &mut self,
        id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError>;

    // ---- Rotation schedule ----

    /// When the signed and last-resort Kyber pre-keys were last rotated, or
    /// `None` if they never have been.
    ///
    /// Both keys rotate together in a single upload, so one timestamp covers
    /// both.
    async fn last_prekey_rotation(
        &self,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, SignalProtocolError>;

    /// Records when the signed and last-resort Kyber pre-keys were rotated.
    ///
    /// Written by [`mark_signed_pre_keys_active`], so a failed upload leaves
    /// the schedule untouched and is retried on the next refresh.
    ///
    /// [`mark_signed_pre_keys_active`]: PreKeysStore::mark_signed_pre_keys_active
    async fn set_last_prekey_rotation(
        &mut self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    // ---- Staleness / cleanup hooks ----

    /// Analogous to markAllOneTimeEcPreKeysStaleIfNecessary
    async fn mark_stale_one_time_ec_pre_keys(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    /// Analogue of deleteAllStaleOneTimeEcPreKeys
    async fn delete_all_stale_one_time_ec_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count_to_keep: usize,
    ) -> Result<(), SignalProtocolError>;

    // ---- Composed operations (default methods) ----

    /// Whether the signed and last-resort Kyber pre-keys are due for rotation.
    ///
    /// Due if never rotated, or if the last rotation is older than
    /// [`PRE_KEY_ROTATION_INTERVAL`].
    ///
    /// One-time pre-keys are deliberately not considered: their replenishment
    /// is gated on the *server's* remaining count, and the local count is not a
    /// usable proxy — the local pool stays full while the server hands its
    /// copies out.
    ///
    /// Implementors may override this to use a different schedule.
    async fn signed_pre_keys_due_for_rotation(
        &self,
    ) -> Result<bool, SignalProtocolError> {
        Ok(match self.last_prekey_rotation().await? {
            None => true, // never rotated
            Some(ts) => chrono::Utc::now() - ts > PRE_KEY_ROTATION_INTERVAL,
        })
    }

    /// Records the signed / last-resort ids the server has accepted as active,
    /// and stamps the rotation.
    ///
    /// Call only after the upload succeeds. [`clean_stale_pre_keys`] uses
    /// these to preserve the live published keys; setting them beforehand
    /// risks pointing `active` at a key the server never accepted, and would
    /// start the rotation interval on keys the server never took.
    ///
    /// [`clean_stale_pre_keys`]: PreKeysStore::clean_stale_pre_keys
    async fn mark_signed_pre_keys_active(
        &mut self,
        signed_pre_key: &SignedPreKeyRecord,
        pq_last_resort_key: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.set_active_signed_prekey_id(signed_pre_key.id()?)
            .await?;

        self.set_active_last_resort_kyber_prekey_id(pq_last_resort_key.id()?)
            .await?;

        self.set_last_prekey_rotation(chrono::Utc::now()).await?;

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
}

impl TryFrom<PreKeyRecord> for PreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: PreKeyRecord) -> Result<Self, Self::Error> {
        Ok(PreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

impl TryFrom<&'_ SignedPreKeyRecord> for SignedPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: &'_ SignedPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(SignedPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?.to_vec(),
        })
    }
}

impl TryFrom<SignedPreKeyRecord> for SignedPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: SignedPreKeyRecord) -> Result<Self, Self::Error> {
        SignedPreKeyEntity::try_from(&key)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KyberPreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

impl TryFrom<&'_ KyberPreKeyRecord> for KyberPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: &'_ KyberPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(KyberPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?,
        })
    }
}

impl TryFrom<KyberPreKeyRecord> for KyberPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: KyberPreKeyRecord) -> Result<Self, Self::Error> {
        KyberPreKeyEntity::try_from(&key)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_keys: Option<Vec<PreKeyEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_pre_key: Option<SignedPreKeyEntity>,
    #[serde(with = "serde_identity_key")]
    pub identity_key: IdentityKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_last_resort_key: Option<KyberPreKeyEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_pre_keys: Option<Vec<KyberPreKeyEntity>>,
}

/// Id following `id`, wrapped into the 1-based id space.
fn wrap_next(id: u32) -> u32 {
    (id % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1
}

pub(crate) const PRE_KEY_MINIMUM: u32 = 10;
pub(crate) const PRE_KEY_BATCH_SIZE: u32 = 100;
pub(crate) const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;
/// How often the signed and last-resort Kyber pre-keys are rotated.
/// Upstream's PreKeysSyncJob uses roughly this interval.
pub const PRE_KEY_ROTATION_INTERVAL: chrono::Duration =
    chrono::Duration::days(2);

pub(crate) async fn replenish_pre_keys<R: Rng + CryptoRng, P: PreKeysStore>(
    protocol_store: &mut P,
    csprng: &mut R,
    identity_key_pair: &IdentityKeyPair,
    use_last_resort_key: bool,
    pre_key_count: u32,
    kyber_pre_key_count: u32,
) -> Result<
    (
        Vec<PreKeyRecord>,
        SignedPreKeyRecord,
        Vec<KyberPreKeyRecord>,
        Option<KyberPreKeyRecord>,
    ),
    SignalProtocolError,
> {
    let pre_keys_offset_id = protocol_store.last_pre_key_id().await?;
    let next_signed_pre_key_id =
        wrap_next(protocol_store.last_signed_pre_key_id().await?);
    let pq_pre_keys_offset_id = protocol_store.last_pq_pre_key_id().await?;

    let span = tracing::span!(tracing::Level::DEBUG, "Generating pre keys");

    let mut pre_keys = vec![];
    let mut pq_pre_keys = vec![];

    // EC keys
    for i in 0..pre_key_count {
        let key_pair = KeyPair::generate(csprng);
        let pre_key_id =
            (((pre_keys_offset_id + i) % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1)
                .into();
        let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);
        protocol_store
                    .save_pre_key(pre_key_id, &pre_key_record)
                    .instrument(tracing::trace_span!(parent: &span, "save pre key", ?pre_key_id)).await?;
        // TODO: Shouldn't this also remove the previous pre-keys from storage?
        //       I think we might want to update the storage, and then sync the storage to the
        //       server.

        pre_keys.push(pre_key_record);
    }

    // Kyber keys
    for i in 0..kyber_pre_key_count {
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
                    .instrument(tracing::trace_span!(parent: &span, "save kyber pre key", ?pre_key_id)).await?;
        // TODO: Shouldn't this also remove the previous pre-keys from storage?
        //       I think we might want to update the storage, and then sync the storage to the
        //       server.

        pq_pre_keys.push(pre_key_record);
    }

    // Generate and store the next signed prekey
    let signed_pre_key_pair = KeyPair::generate(csprng);
    let signed_pre_key_public = signed_pre_key_pair.public_key;
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_public.serialize(), csprng)?;

    let signed_prekey_record = SignedPreKeyRecord::new(
        next_signed_pre_key_id.into(),
        Timestamp::now(),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );

    protocol_store
                .save_signed_pre_key(
                    next_signed_pre_key_id.into(),
                    &signed_prekey_record,
                )
                    .instrument(tracing::trace_span!(parent: &span, "save signed pre key", signed_pre_key_id = ?next_signed_pre_key_id)).await?;

    let pq_last_resort_key = if use_last_resort_key {
        let pre_key_id = (((pq_pre_keys_offset_id + kyber_pre_key_count)
            % (PRE_KEY_MEDIUM_MAX_VALUE - 1))
            + 1)
        .into();

        if !pq_pre_keys.is_empty() {
            assert_eq!(
                u32::from(pq_pre_keys.last().unwrap().id()?) + 1,
                u32::from(pre_key_id)
            );
        }

        let pre_key_record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            pre_key_id,
            identity_key_pair.private_key(),
        )?;
        protocol_store
                    .store_last_resort_kyber_pre_key(pre_key_id, &pre_key_record)
                    .instrument(tracing::trace_span!(parent: &span, "save last resort kyber pre key", ?pre_key_id)).await?;
        // TODO: Shouldn't this also remove the previous pre-keys from storage?
        //       I think we might want to update the storage, and then sync the storage to the
        //       server.

        Some(pre_key_record)
    } else {
        None
    };

    Ok((
        pre_keys,
        signed_prekey_record,
        pq_pre_keys,
        pq_last_resort_key,
    ))
}
