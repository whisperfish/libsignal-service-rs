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

    /// Persist a rotated signed pre-key (and last-resort kyber key) and
    /// record the ids issued.
    ///
    /// One-time keys are untouched: a signed rotation does not supersede them,
    /// so nothing is marked stale here.
    ///
    /// Active ids are NOT set — call [`mark_signed_pre_keys_active`] after the
    /// upload succeeds.
    ///
    /// [`mark_signed_pre_keys_active`]: PreKeysStore::mark_signed_pre_keys_active
    async fn store_signed_pre_key_bundle(
        &mut self,
        signed_pre_key: &SignedPreKeyRecord,
        pq_last_resort_key: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.save_signed_pre_key(signed_pre_key.id()?, signed_pre_key)
            .await?;

        self.store_last_resort_kyber_pre_key(
            pq_last_resort_key.id()?,
            pq_last_resort_key,
        )
        .await?;

        // ---- Record the issued ids (pre-upload) ----
        self.set_last_signed_pre_key_id(u32::from(signed_pre_key.id()?))
            .await?;

        // The last-resort key shares the kyber id space with one-time keys.
        self.set_last_pq_pre_key_id(u32::from(pq_last_resort_key.id()?))
            .await?;

        Ok(())
    }

    /// Persist a fresh batch of one-time pre-keys and record the ids issued.
    ///
    /// Uploading one-time keys replaces the server's set, so the batch being
    /// superseded is marked stale here: it is no longer offered, and ages out
    /// via [`clean_stale_pre_keys`] after the grace period.
    ///
    /// Each pool is handled independently — a pool is only staled when keys
    /// are actually arriving to replace it, so passing an empty slice leaves
    /// that pool untouched rather than retiring every usable key in it.
    ///
    /// [`clean_stale_pre_keys`]: PreKeysStore::clean_stale_pre_keys
    async fn store_one_time_pre_key_bundle(
        &mut self,
        pre_keys: &[PreKeyRecord],
        pq_pre_keys: &[KyberPreKeyRecord],
    ) -> Result<(), SignalProtocolError> {
        let now = chrono::Utc::now();

        if !pre_keys.is_empty() {
            self.mark_stale_one_time_ec_pre_keys(now).await?;
            for key in pre_keys {
                self.save_pre_key(key.id()?, key).await?;
            }

            // Record the last id of the batch (pre-upload).
            let last = pre_keys.last().expect("non-empty");
            self.set_last_pre_key_id(u32::from(last.id()?)).await?;
        }

        if !pq_pre_keys.is_empty() {
            self.mark_stale_one_time_kyber_pre_keys(now).await?;
            // libsignal draws no last-resort distinction: plain
            // `save_kyber_pre_key` is the one-time path.
            for key in pq_pre_keys {
                self.save_kyber_pre_key(key.id()?, key).await?;
            }

            let last = pq_pre_keys.last().expect("non-empty");
            self.set_last_pq_pre_key_id(u32::from(last.id()?)).await?;
        }

        Ok(())
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

    /// Archive superseded signed / last-resort keys and delete stale one-time
    /// keys.
    ///
    /// Signed and last-resort keys older than `ARCHIVE_AGE` are removed, all
    /// but the youngest and the currently active one. One-time keys marked
    /// stale longer than `STALE_AGE` are deleted while preserving at least
    /// `ONE_TIME_MIN_COUNT`.
    ///
    /// Run only after a successful upload, so the active ids reflect
    /// server-confirmed keys.
    async fn clean_stale_pre_keys(
        &mut self,
    ) -> Result<(), SignalProtocolError> {
        let now = chrono::Utc::now();
        let now_ms = now.timestamp_millis() as u64;
        let one_time_threshold = now - STALE_AGE;

        if let Some(active) = self.active_signed_prekey_id().await? {
            let keys = self.load_signed_pre_keys().await?;
            let stale = collect_archived(active, keys, now_ms, |r| {
                Some((r.id().ok()?, r.timestamp().ok()?.epoch_millis()))
            });
            for (id, ts) in stale.into_iter().skip(1) {
                tracing::debug!(?id, ts, "removing old signed pre-key");
                self.remove_signed_pre_key(id).await?;
            }
        }

        if let Some(active) = self.active_last_resort_kyber_prekey_id().await? {
            let keys = self.load_last_resort_kyber_pre_keys().await?;
            let stale = collect_archived(active, keys, now_ms, |r| {
                Some((r.id().ok()?, r.timestamp().ok()?.epoch_millis()))
            });
            for (id, ts) in stale.into_iter().skip(1) {
                tracing::debug!(
                    ?id,
                    ts,
                    "removing old last-resort kyber pre-key"
                );
                self.remove_kyber_pre_key(id).await?;
            }
        }

        self.delete_all_stale_one_time_ec_pre_keys(
            one_time_threshold,
            ONE_TIME_MIN_COUNT,
        )
        .await?;
        self.delete_all_stale_one_time_kyber_pre_keys(
            one_time_threshold,
            ONE_TIME_MIN_COUNT,
        )
        .await?;

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

const ARCHIVE_AGE: chrono::Duration = chrono::Duration::days(30);
const STALE_AGE: chrono::Duration = chrono::Duration::days(90);
const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;
pub(crate) const PRE_KEY_BATCH_SIZE: u32 = 100;
/// Minimum amount of active and stale keys combined to ensure
/// stale keys are never removed prematurely: two batches, so the
/// superseded generation survives until the one after it arrives.
const ONE_TIME_MIN_COUNT: usize = 2 * PRE_KEY_BATCH_SIZE as usize;
/// Replenish one-time keys when the server holds fewer than this.
pub(crate) const PRE_KEY_MINIMUM: u32 = 10;
/// How often the signed and last-resort Kyber pre-keys are rotated.
/// Upstream's PreKeysSyncJob uses roughly this interval.
pub const PRE_KEY_ROTATION_INTERVAL: chrono::Duration =
    chrono::Duration::days(2);

/// Generate a fresh signed pre-key and a last-resort kyber
/// pre-key. Nothing is persisted — pass the result to
/// [`store_signed_pre_key_bundle`].
///
/// Note the kyber id space is shared with one-time kyber keys: generate
/// and store one kind before generating the other, or both will claim the
/// same `last_pq_pre_key_id`.
///
/// Public only for use in testing in clients.
///
/// [`store_signed_pre_key_bundle`]: PreKeysStore::store_signed_pre_key_bundle
pub async fn generate_signed_pre_keys<R: Rng + CryptoRng, P: PreKeysStore>(
    protocol_store: &mut P,
    csprng: &mut R,
    identity_key_pair: &IdentityKeyPair,
) -> Result<(SignedPreKeyRecord, KyberPreKeyRecord), SignalProtocolError> {
    let last_signed_pre_key_id =
        protocol_store.last_signed_pre_key_id().await?;
    let last_pq_pre_key_id = protocol_store.last_pq_pre_key_id().await?;

    let _span =
        tracing::span!(tracing::Level::DEBUG, "Generating signed pre keys")
            .entered();

    let signed_pre_key_pair = KeyPair::generate(csprng);
    let signed_pre_key_signature =
        identity_key_pair.private_key().calculate_signature(
            &signed_pre_key_pair.public_key.serialize(),
            csprng,
        )?;

    let signed_pre_key = SignedPreKeyRecord::new(
        wrap_next(last_signed_pre_key_id).into(),
        Timestamp::now(),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );

    let pq_last_resort_key = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        wrap_next(last_pq_pre_key_id).into(),
        identity_key_pair.private_key(),
    )?;

    Ok((signed_pre_key, pq_last_resort_key))
}

/// Generate one-time EC and kyber pre-keys. Nothing is persisted — pass
/// the result to [`store_one_time_pre_key_bundle`].
///
/// Public only for use in testing in clients.
///
/// [`store_one_time_pre_key_bundle`]: PreKeysStore::store_one_time_pre_key_bundle
pub async fn generate_one_time_pre_keys<R: Rng + CryptoRng, P: PreKeysStore>(
    protocol_store: &mut P,
    csprng: &mut R,
    identity_key_pair: &IdentityKeyPair,
    ec_count: u32,
    kyber_count: u32,
) -> Result<(Vec<PreKeyRecord>, Vec<KyberPreKeyRecord>), SignalProtocolError> {
    let last_pre_key_id = protocol_store.last_pre_key_id().await?;
    let last_pq_pre_key_id = protocol_store.last_pq_pre_key_id().await?;

    let _span =
        tracing::span!(tracing::Level::DEBUG, "Generating one-time pre keys")
            .entered();

    let mut pre_keys = Vec::with_capacity(ec_count as usize);
    for i in 0..ec_count {
        let key_pair = KeyPair::generate(csprng);
        let id = wrap_next(last_pre_key_id + i).into();
        pre_keys.push(PreKeyRecord::new(id, &key_pair));
    }

    let mut pq_pre_keys = Vec::with_capacity(kyber_count as usize);
    for i in 0..kyber_count {
        let id = wrap_next(last_pq_pre_key_id + i).into();
        pq_pre_keys.push(KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id,
            identity_key_pair.private_key(),
        )?);
    }

    Ok((pre_keys, pq_pre_keys))
}

/// Filter records older than ARCHIVE_AGE,
/// excluding the active id, sorted newest-first.
fn collect_archived<R, I>(
    active_id: I,
    records: Vec<R>,
    now_ms: u64,
    extract: impl Fn(&R) -> Option<(I, u64)>,
) -> Vec<(I, u64)>
where
    I: PartialEq + Copy,
{
    let mut stale: Vec<_> = records
        .into_iter()
        .filter_map(|r| {
            let (id, ts) = extract(&r)?;
            if id == active_id {
                return None;
            }
            (now_ms.saturating_sub(ts) > ARCHIVE_AGE.num_milliseconds() as _)
                .then_some((id, ts))
        })
        .collect();
    stale.sort_by_key(|x| std::cmp::Reverse(x.1));
    stale
}
