use rand::{CryptoRng, Rng};

const MASTER_KEY_LEN: usize = 32;
const STORAGE_KEY_LEN: usize = 32;

#[derive(Debug, PartialEq)]
pub struct MasterKey {
    pub inner: [u8; MASTER_KEY_LEN],
}

impl MasterKey {
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        // Create random bytes
        let mut inner = [0_u8; MASTER_KEY_LEN];
        csprng.fill(&mut inner);
        Self { inner }
    }

    pub fn from_slice(
        slice: &[u8],
    ) -> Result<Self, std::array::TryFromSliceError> {
        let inner = slice.try_into()?;
        Ok(Self { inner })
    }
}

impl From<MasterKey> for Vec<u8> {
    fn from(val: MasterKey) -> Self {
        val.inner.to_vec()
    }
}

#[derive(Debug, PartialEq)]
pub struct StorageServiceKey {
    pub inner: [u8; STORAGE_KEY_LEN],
}

impl StorageServiceKey {
    pub fn from_master_key(master_key: &MasterKey) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        const KEY: &[u8] = b"Storage Service Encryption";

        let mut mac = HmacSha256::new_from_slice(&master_key.inner).unwrap();
        mac.update(KEY);
        let result = mac.finalize();
        let inner: [u8; STORAGE_KEY_LEN] = result.into_bytes().into();

        Self { inner }
    }

    pub fn from_slice(
        slice: &[u8],
    ) -> Result<Self, std::array::TryFromSliceError> {
        let inner = slice.try_into()?;
        Ok(Self { inner })
    }
}

impl From<StorageServiceKey> for Vec<u8> {
    fn from(val: StorageServiceKey) -> Self {
        val.inner.to_vec()
    }
}

/// Storage trait for handling MasterKey and StorageKey.
pub trait MasterKeyStore {
    /// Fetch the master key from the store if it exists.
    fn fetch_master_key(&self) -> Option<MasterKey>;

    /// Fetch the storage service key from the store if it exists.
    fn fetch_storage_service_key(&self) -> Option<StorageServiceKey>;

    /// Save (or clear) the master key to the store.
    fn store_master_key(&self, master_key: Option<&MasterKey>);

    /// Save (or clear) the storage service key to the store.
    fn store_storage_service_key(
        &self,
        storage_key: Option<&StorageServiceKey>,
    );
}

mod tests {
    #[test]
    fn derive_storage_key_from_master_key() {
        use super::{MasterKey, StorageServiceKey};
        use base64::prelude::*;

        // This test passed with actual 'masterKey' and 'storageKey' values taken
        // from Signal Desktop v7.23.0 database at 2024-09-08 after linking it with Signal Andoid.

        let master_key_bytes = BASE64_STANDARD
            .decode("9hquLIIZmom8fHF7H8pbUAreawmPLEqli5ceJ94pFkU=")
            .unwrap();
        let storage_key_bytes = BASE64_STANDARD
            .decode("QMgZ5RGTLFTr4u/J6nypaJX6DKDlSgMw8vmxU6gxnvI=")
            .unwrap();
        assert_eq!(master_key_bytes.len(), 32);
        assert_eq!(storage_key_bytes.len(), 32);

        let master_key = MasterKey::from_slice(&master_key_bytes).unwrap();
        let storage_key = StorageServiceKey::from_master_key(&master_key);

        assert_eq!(master_key.inner, master_key_bytes.as_slice());
        assert_eq!(storage_key.inner, storage_key_bytes.as_slice());
    }
}
