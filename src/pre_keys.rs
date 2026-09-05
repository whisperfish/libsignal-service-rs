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
/// wrap, starting from 1) is performed by libsignal-service-rs orchestration after key
/// generation, then written via the setter. The `store_one_time_*` methods
/// likewise only persist records; they do NOT advance next-ids.
///
/// ## Active-ID contract
///
/// `set_active_*` records the id the server has accepted. Orchestration calls
/// these only after a successful upload, so `clean_*` excludes the correct
/// live key. The matching getters return `None` before the first upload.
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
    pub pre_keys: Vec<PreKeyEntity>,
    pub signed_pre_key: SignedPreKeyEntity,
    #[serde(with = "serde_identity_key")]
    pub identity_key: IdentityKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_last_resort_key: Option<KyberPreKeyEntity>,
    pub pq_pre_keys: Vec<KyberPreKeyEntity>,
}

pub(crate) const PRE_KEY_BATCH_SIZE: u32 = 100;
pub(crate) const PRE_KEY_MEDIUM_MAX_VALUE: u32 = 0xFFFFFF;

fn wrap_next(id: u32) -> u32 {
    (id % (PRE_KEY_MEDIUM_MAX_VALUE - 1)) + 1
}

/// Generate in-memory pre-keys for the caller to persist as needed.
pub(crate) async fn generate_pre_keys<R: Rng + CryptoRng, P: PreKeysStore>(
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
    let pre_keys_offset_id = protocol_store.next_pre_key_id().await?;
    let next_signed_pre_key_id =
        protocol_store.next_signed_pre_key_id().await?;
    let pq_pre_keys_offset_id = protocol_store.next_pq_pre_key_id().await?;

    let _span =
        tracing::span!(tracing::Level::DEBUG, "Generating pre keys").entered();

    let mut pre_keys = vec![];
    let mut pq_pre_keys = vec![];

    // EC keys
    for i in 0..pre_key_count {
        let key_pair = KeyPair::generate(csprng);
        let pre_key_id = wrap_next(pre_keys_offset_id + i).into();
        let pre_key_record = PreKeyRecord::new(pre_key_id, &key_pair);

        pre_keys.push(pre_key_record);
    }

    // Kyber keys
    for i in 0..kyber_pre_key_count {
        let pre_key_id = wrap_next(pq_pre_keys_offset_id + i).into();
        let pre_key_record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            pre_key_id,
            identity_key_pair.private_key(),
        )?;

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

    let pq_last_resort_key = if use_last_resort_key {
        let pre_key_id =
            wrap_next(pq_pre_keys_offset_id + kyber_pre_key_count).into();

        let pre_key_record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            pre_key_id,
            identity_key_pair.private_key(),
        )?;

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

/// Stores a complete pre-key bundle to the protocol store.
///
/// Marks existing one-time pre-keys as stale (preserved for grace period),
/// inserts the new keys, then advances the next-id counters and records the
/// active signed / last-resort ids. The store's `set_next_*` / `set_active_*`
/// are pure persistence — all advancing happens here.
///
/// Caller invokes the cleanup helpers (`clean_signed_pre_keys`,
/// `clean_one_time_pre_keys`, etc.) after the bundle is uploaded.
pub(crate) async fn store_pre_key_bundle<P: PreKeysStore>(
    protocol_store: &mut P,
    pre_keys: &[PreKeyRecord],
    signed_pre_key: &SignedPreKeyRecord,
    pq_pre_keys: &[KyberPreKeyRecord],
    pq_last_resort_key: Option<&KyberPreKeyRecord>,
) -> Result<(), SignalProtocolError> {
    let now = chrono::Utc::now();

    // Mark old one-time keys as stale before inserting new ones
    protocol_store
        .mark_all_one_time_ec_pre_keys_stale_if_necessary(now)
        .await?;
    protocol_store
        .mark_all_one_time_kyber_pre_keys_stale_if_necessary(now)
        .await?;

    // Insert new EC one-time pre-keys
    for k in pre_keys {
        protocol_store.save_pre_key(k.id()?, k).await?;
    }

    // Insert new Kyber one-time pre-keys
    for k in pq_pre_keys {
        protocol_store.save_kyber_pre_key(k.id()?, k).await?;
    }

    // Persist signed pre-key
    protocol_store
        .save_signed_pre_key(signed_pre_key.id()?, signed_pre_key)
        .await?;

    // Persist last-resort Kyber key if present
    if let Some(k) = pq_last_resort_key {
        protocol_store
            .store_last_resort_kyber_pre_key(k.id()?, k)
            .await?;
    }

    // ---- Advance next-ids (pre-upload, Android model) ----
    // Store setters only persist; the advance is computed here.

    if let Some(last) = pre_keys.last() {
        let next = wrap_next(u32::from(last.id()?));
        protocol_store.set_next_pre_key_id(next).await?;
    }

    // Kyber next-id must account for the last-resort key, which is generated
    // one past the one-time batch and shares the kyber id space. Advance from
    // whichever id is highest: last-resort if present, else the batch tail.
    let pq_advance_from = pq_last_resort_key
        .map(|k| k.id())
        .or_else(|| pq_pre_keys.last().map(|k| k.id()))
        .transpose()?;
    if let Some(id) = pq_advance_from {
        let next = wrap_next(u32::from(id));
        protocol_store.set_next_pq_pre_key_id(next).await?;
    }

    // Signed pre-key is a single key, not a batch.
    {
        let next = wrap_next(u32::from(signed_pre_key.id()?));
        protocol_store.set_next_signed_pre_key_id(next).await?;
    }

    // Active prekey and kyber prekey id's set post upload.

    Ok(())
}

const ARCHIVE_AGE: chrono::Duration = chrono::Duration::days(30);
const STALE_AGE: chrono::Duration = chrono::Duration::days(90);
const ONE_TIME_MIN_COUNT: usize = 200;

pub async fn clean_stale_pre_keys<P: PreKeysStore>(
    protocol_store: &mut P,
) -> Result<(), SignalProtocolError> {
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis() as u64;
    let one_time_threshold = now - STALE_AGE;

    if let Some(active) = protocol_store.active_signed_prekey_id().await? {
        let keys = protocol_store.load_signed_pre_keys().await?;
        let stale = collect_archived(active, keys, now_ms, |r| {
            Some((r.id().ok()?, r.timestamp().ok()?.epoch_millis()))
        });
        for (id, ts) in stale.into_iter().skip(1) {
            tracing::debug!(?id, ts, "removing old signed pre-key");
            protocol_store.remove_signed_pre_key(id).await?;
        }
    }

    if let Some(active) = protocol_store.last_resort_kyber_prekey_id().await? {
        let keys = protocol_store.load_last_resort_kyber_pre_keys().await?;
        let stale = collect_archived(active, keys, now_ms, |r| {
            Some((r.id().ok()?, r.timestamp().ok()?.epoch_millis()))
        });
        for (id, ts) in stale.into_iter().skip(1) {
            tracing::debug!(?id, ts, "removing old last-resort kyber pre-key");
            protocol_store.remove_kyber_pre_key(id).await?;
        }
    }

    protocol_store
        .delete_all_stale_one_time_ec_pre_keys(
            one_time_threshold,
            ONE_TIME_MIN_COUNT,
        )
        .await?;
    protocol_store
        .delete_all_stale_one_time_kyber_pre_keys(
            one_time_threshold,
            ONE_TIME_MIN_COUNT,
        )
        .await?;
    Ok(())
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

/// Records the signed / last-resort ids the server has accepted as active.
///
/// Call only after the pre-key bundle upload succeeds. `clean_*` uses these
/// to preserve the live published keys; setting them before upload risks
/// pointing `active` at a key the server never accepted.
pub(crate) async fn mark_pre_key_bundle_active<P: PreKeysStore>(
    protocol_store: &mut P,
    signed_pre_key: &SignedPreKeyRecord,
    pq_last_resort_key: Option<&KyberPreKeyRecord>,
) -> Result<(), SignalProtocolError> {
    protocol_store
        .set_active_signed_prekey_id(signed_pre_key.id()?)
        .await?;

    if let Some(k) = pq_last_resort_key {
        protocol_store
            .set_active_last_resort_kyber_prekey_id(k.id()?)
            .await?;
    }

    Ok(())
}
