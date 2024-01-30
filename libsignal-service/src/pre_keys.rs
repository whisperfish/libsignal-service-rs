use std::{convert::TryFrom, time::SystemTime};

use crate::utils::{serde_base64, serde_public_key};
use async_trait::async_trait;
use libsignal_protocol::{
    error::SignalProtocolError, kem, GenericSignedPreKey, IdentityKeyStore,
    KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyRecord,
    PreKeyStore, PublicKey, SignedPreKeyRecord, SignedPreKeyStore,
};

use serde::{Deserialize, Serialize};

#[async_trait(?Send)]
/// Additional methods for the Kyber pre key store
///
/// Analogue of Android's ServiceKyberPreKeyStore
pub trait ServiceKyberPreKeyStore: KyberPreKeyStore {
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

/// Stores the ID of keys published ahead of time
///
/// <https://signal.org/docs/specifications/x3dh/>
#[async_trait(?Send)]
pub trait PreKeysStore:
    PreKeyStore
    + IdentityKeyStore
    + SignedPreKeyStore
    + KyberPreKeyStore
    + ServiceKyberPreKeyStore
{
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError>;

    /// set the ID of the next pre key
    async fn set_next_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    /// set the ID of the next signed pre key
    async fn set_next_signed_pre_key_id(
        &mut self,
        id: u32,
    ) -> Result<(), SignalProtocolError>;

    /// set the ID of the next PQ pre key
    async fn set_next_pq_pre_key_id(
        &mut self,
        id: u32,
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

impl TryFrom<SignedPreKeyRecord> for SignedPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: SignedPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(SignedPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?.to_vec(),
        })
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

impl TryFrom<KyberPreKeyRecord> for KyberPreKeyEntity {
    type Error = SignalProtocolError;

    fn try_from(key: KyberPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(KyberPreKeyEntity {
            key_id: key.id()?.into(),
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
            signature: key.signature()?,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyState {
    pub pre_keys: Vec<PreKeyEntity>,
    pub signed_pre_key: SignedPreKeyEntity,
    #[serde(with = "serde_public_key")]
    pub identity_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_last_resort_key: Option<KyberPreKeyEntity>,
    pub pq_pre_keys: Vec<KyberPreKeyEntity>,
}

pub(crate) async fn generate_last_resort_kyber_key<S: PreKeysStore>(
    store: &mut S,
    identity_key: &KeyPair,
) -> Result<KyberPreKeyRecord, SignalProtocolError> {
    let id = store.next_pq_pre_key_id().await?;
    let id = id.max(1); // TODO: Hack, keys start with 1

    let record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        id.into(),
        &identity_key.private_key,
    )?;

    store.save_kyber_pre_key(id.into(), &record).await?;
    store.set_next_pq_pre_key_id(id + 1).await?;

    Ok(record)
}

pub(crate) async fn generate_signed_pre_key<
    S: PreKeysStore,
    R: rand::Rng + rand::CryptoRng,
>(
    store: &mut S,
    csprng: &mut R,
    identity_key: &KeyPair,
) -> Result<SignedPreKeyRecord, SignalProtocolError> {
    let id = store.next_signed_pre_key_id().await?;
    let id = id.max(1); // TODO: Hack, keys start with 1

    let key_pair = KeyPair::generate(csprng);
    let signature = identity_key
        .private_key
        .calculate_signature(&key_pair.public_key.serialize(), csprng)?;

    let unix_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let record =
        SignedPreKeyRecord::new(id.into(), unix_time, &key_pair, &signature);

    store.save_signed_pre_key(id.into(), &record).await?;
    store.set_next_signed_pre_key_id(id + 1).await?;

    Ok(record)
}
