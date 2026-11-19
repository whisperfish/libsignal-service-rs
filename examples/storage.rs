use libsignal_service::pre_keys::{KyberPreKeyStoreExt, PreKeysStore};
use libsignal_service::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord,
    PreKeyStore, ProtocolAddress, PublicKey, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};

#[derive(Default)]
pub struct ExampleStore {}

impl ExampleStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl PreKeyStore for ExampleStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(
        &self,
        _prekey_id: PreKeyId,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        todo!()
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        _prekey_id: PreKeyId,
        _record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(
        &mut self,
        _prekey_id: PreKeyId,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl KyberPreKeyStore for ExampleStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(
        &self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        todo!()
    }

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    /// Mark the entry for `kyber_prekey_id` as "used".
    /// This would mean different things for one-time and last-resort Kyber keys.
    async fn mark_kyber_pre_key_used(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl SignedPreKeyStore for ExampleStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        _signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        todo!()
    }

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        _signed_prekey_id: SignedPreKeyId,
        _record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl KyberPreKeyStoreExt for ExampleStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
        _record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        todo!()
    }

    async fn remove_kyber_pre_key(
        &mut self,
        _kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _threshold: chrono::DateTime<chrono::Utc>,
        _min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl IdentityKeyStore for ExampleStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        todo!()
    }

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, SignalProtocolError> {
        todo!()
    }

    // TODO: make this into an enum instead of a bool!
    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value should be `Ok(false)`.
    async fn save_identity(
        &mut self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        todo!()
    }

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        todo!()
    }

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        _address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
#[allow(clippy::diverging_sub_expression)]
impl PreKeysStore for ExampleStore {
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        todo!()
    }

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        todo!()
    }

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        todo!()
    }

    async fn signed_pre_keys_count(
        &self,
    ) -> Result<usize, SignalProtocolError> {
        todo!()
    }

    async fn kyber_pre_keys_count(
        &self,
        _last_resort: bool,
    ) -> Result<usize, SignalProtocolError> {
        todo!()
    }

    async fn signed_prekey_id(
        &self,
    ) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        todo!()
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        todo!()
    }
}

#[allow(dead_code)]
fn main() {
    let _ = ExampleStore::new();
}
