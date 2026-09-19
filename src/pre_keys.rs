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
pub trait KyberPreKeyStoreExt: KyberPreKeyStore {
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
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count: usize,
    ) -> Result<(), SignalProtocolError>;
}

#[async_trait(?Send)]
/// Additional methods for the signed pre key store
pub trait SignedPreKeyStoreExt: SignedPreKeyStore {
    async fn load_signed_pre_keys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecord>, SignalProtocolError>;

    async fn remove_signed_pre_key(
        &self,
        pre_key_id: SignedPreKeyId,
    ) -> Result<(), SignalProtocolError>;
}

/// Stores the ID of keys published ahead of time
///
/// <https://signal.org/docs/specifications/x3dh/>
///
/// ## Next-ID advance contract
///
/// Implementors of the `set_next_*` setters MUST treat them as plain
/// persistence: write the value, return. They MUST NOT advance, wrap, or
/// otherwise mutate the id. All advancing (increment + `% PRE_KEY_MEDIUM_MAX_VALUE`
/// wrap, starting from 1) is performed by the `store_pre_key_bundle` default
/// method after key generation, then written via the setter. The
/// `store_one_time_*` methods likewise only persist records; they do NOT
/// advance next-ids.
///
/// ## Active-ID contract
///
/// `set_active_*` records the id the server has accepted. `store_pre_key_bundle`
/// does NOT set them; call `mark_pre_key_bundle_active` only after a successful
/// upload, so `clean_stale_pre_keys` excludes the correct live key. The matching
/// getters return `None` before the first upload.
#[async_trait(?Send)]
pub trait PreKeysStore:
    PreKeyStore
    + IdentityKeyStore
    + SignedPreKeyStore
    + SignedPreKeyStoreExt
    + KyberPreKeyStore
    + KyberPreKeyStoreExt
{
    // ---- Next-ID getters ----

    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    // ---- Next-ID setters (persistence only; do NOT advance) ----

    async fn set_next_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    async fn set_next_signed_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    async fn set_next_pq_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    // ---- Counts ----

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self)
        -> Result<usize, SignalProtocolError>;

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(
        &self,
        last_resort: bool,
    ) -> Result<usize, SignalProtocolError>;

    /// number of one-time EC pre-keys we currently have in store
    async fn ec_one_time_pre_keys_count(
        &self,
    ) -> Result<usize, SignalProtocolError>;

    // ---- Active-ID getters ----

    async fn active_signed_prekey_id(
        &self,
    ) -> Result<Option<SignedPreKeyId>, SignalProtocolError>;

    async fn last_resort_kyber_prekey_id(
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

    // ---- One-time key storage (persistence only; do NOT advance next-ids) ----

    async fn store_one_time_ec_pre_keys(
        &mut self,
        keys: &[PreKeyRecord],
    ) -> Result<(), SignalProtocolError>;

    async fn store_one_time_kyber_pre_keys(
        &mut self,
        keys: &[KyberPreKeyRecord],
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
    /// Called only after a successful upload, so a failed rotation leaves the
    /// schedule untouched and is retried on the next refresh.
    async fn set_last_prekey_rotation(
        &mut self,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    // ---- Staleness / cleanup hooks ----

    /// Analogous to markAllOneTimeEcPreKeysStaleIfNecessary
    async fn mark_all_one_time_ec_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError>;

    /// Analogue of deleteAllStaleOneTimeEcPreKeys
    async fn delete_all_stale_one_time_ec_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count: usize,
    ) -> Result<(), SignalProtocolError>;

    // ---- Composed operations (default methods) ----

    /// Whether the signed and last-resort Kyber pre-keys are due for rotation.
    ///
    /// Due if any of:
    /// - no signed pre-key,
    /// - no last-resort Kyber pre-key,
    /// - never rotated,
    /// - the last rotation is older than [`PRE_KEY_ROTATION_INTERVAL`].
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
        if self.signed_pre_keys_count().await? == 0 {
            return Ok(true);
        }
        if self.kyber_pre_keys_count(true).await? == 0 {
            return Ok(true);
        }

        Ok(match self.last_prekey_rotation().await? {
            None => true, // never rotated
            Some(ts) => chrono::Utc::now() - ts > PRE_KEY_ROTATION_INTERVAL,
        })
    }

    /// Generate a fresh signed pre-key and a last-resort kyber
    /// pre-key. Nothing is persisted — pass the result to
    /// [`store_signed_pre_key_bundle`].
    ///
    /// Note the kyber id space is shared with one-time kyber keys: generate
    /// and store one kind before generating the other, or both will claim the
    /// same `next_pq_pre_key_id`.
    ///
    /// [`store_signed_pre_key_bundle`]: PreKeysStore::store_signed_pre_key_bundle
    async fn generate_signed_pre_keys<R: Rng + CryptoRng>(
        &self,
        csprng: &mut R,
        identity_key_pair: &IdentityKeyPair,
    ) -> Result<(SignedPreKeyRecord, KyberPreKeyRecord), SignalProtocolError>
    {
        let next_signed_pre_key_id = self.next_signed_pre_key_id().await?;
        let pq_pre_keys_offset_id = self.next_pq_pre_key_id().await?;

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
            next_signed_pre_key_id.into(),
            Timestamp::now(),
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        );

        let pq_last_resort_key = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            wrap_next(pq_pre_keys_offset_id).into(),
            identity_key_pair.private_key(),
        )?;

        Ok((signed_pre_key, pq_last_resort_key))
    }

    /// Generate one-time EC and kyber pre-keys. Nothing is persisted — pass
    /// the result to [`store_one_time_pre_key_bundle`].
    ///
    /// [`store_one_time_pre_key_bundle`]: PreKeysStore::store_one_time_pre_key_bundle
    async fn generate_one_time_pre_keys<R: Rng + CryptoRng>(
        &self,
        csprng: &mut R,
        identity_key_pair: &IdentityKeyPair,
        ec_count: u32,
        kyber_count: u32,
    ) -> Result<(Vec<PreKeyRecord>, Vec<KyberPreKeyRecord>), SignalProtocolError>
    {
        let pre_keys_offset_id = self.next_pre_key_id().await?;
        let pq_pre_keys_offset_id = self.next_pq_pre_key_id().await?;

        let _span = tracing::span!(
            tracing::Level::DEBUG,
            "Generating one-time pre keys"
        )
        .entered();

        let mut pre_keys = Vec::with_capacity(ec_count as usize);
        for i in 0..ec_count {
            let key_pair = KeyPair::generate(csprng);
            let id = wrap_next(pre_keys_offset_id + i).into();
            pre_keys.push(PreKeyRecord::new(id, &key_pair));
        }

        let mut pq_pre_keys = Vec::with_capacity(kyber_count as usize);
        for i in 0..kyber_count {
            let id = wrap_next(pq_pre_keys_offset_id + i).into();
            pq_pre_keys.push(KyberPreKeyRecord::generate(
                kem::KeyType::Kyber1024,
                id,
                identity_key_pair.private_key(),
            )?);
        }

        Ok((pre_keys, pq_pre_keys))
    }

    /// Persist a rotated signed pre-key (and last-resort kyber key) and
    /// advance the corresponding next-ids.
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

        // ---- Advance next-ids (pre-upload) ----
        let next = wrap_next(u32::from(signed_pre_key.id()?));
        self.set_next_signed_pre_key_id(next).await?;

        // The last-resort key shares the kyber id space with one-time keys.
        let next = wrap_next(u32::from(pq_last_resort_key.id()?));
        self.set_next_pq_pre_key_id(next).await?;

        Ok(())
    }

    /// Persist a fresh batch of one-time pre-keys and advance the
    /// corresponding next-ids.
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
            self.mark_all_one_time_ec_pre_keys_stale_if_necessary(now)
                .await?;
            self.store_one_time_ec_pre_keys(pre_keys).await?;

            // Advance the next-id past the batch (pre-upload).
            let last = pre_keys.last().expect("non-empty");
            let next = wrap_next(u32::from(last.id()?));
            self.set_next_pre_key_id(next).await?;
        }

        if !pq_pre_keys.is_empty() {
            self.mark_all_one_time_kyber_pre_keys_stale_if_necessary(now)
                .await?;
            self.store_one_time_kyber_pre_keys(pq_pre_keys).await?;

            let last = pq_pre_keys.last().expect("non-empty");
            let next = wrap_next(u32::from(last.id()?));
            self.set_next_pq_pre_key_id(next).await?;
        }

        Ok(())
    }

    /// Records the signed / last-resort ids the server has accepted as active.
    ///
    /// Call only after the upload succeeds. [`clean_stale_pre_keys`] uses
    /// these to preserve the live published keys; setting them beforehand
    /// risks pointing `active` at a key the server never accepted.
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

        if let Some(active) = self.last_resort_kyber_prekey_id().await? {
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

fn wrap_next(id: u32) -> u32 {
    (id % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1
}

const ARCHIVE_AGE: chrono::Duration = chrono::Duration::days(30);
const STALE_AGE: chrono::Duration = chrono::Duration::days(90);
const ONE_TIME_MIN_COUNT: usize = 200;
const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;
pub(crate) const PRE_KEY_BATCH_SIZE: u32 = 100;
/// Replenish one-time keys when the server holds fewer than this.
pub(crate) const PRE_KEY_MINIMUM: u32 = 10;
/// How often the signed and last-resort Kyber pre-keys are rotated.
/// Upstream's PreKeysSyncJob uses roughly this interval.
pub const PRE_KEY_ROTATION_INTERVAL: chrono::Duration =
    chrono::Duration::days(2);

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
