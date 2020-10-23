use crate::utils::{serde_base64, serde_public_key};
use libsignal_protocol::keys::{PreKey, PublicKey, SessionSignedPreKey};

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyEntity {
    key_id: u32,
    #[serde(serialize_with = "serde_public_key::serialize")]
    public_key: PublicKey,
}

impl From<PreKey> for PreKeyEntity {
    fn from(key: PreKey) -> PreKeyEntity {
        PreKeyEntity {
            key_id: key.id(),
            public_key: key.key_pair().public(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKey {
    key_id: u32,
    #[serde(with = "serde_public_key")]
    public_key: PublicKey,
    #[serde(with = "serde_base64")]
    signature: Vec<u8>,
}

impl From<SessionSignedPreKey> for SignedPreKey {
    fn from(key: SessionSignedPreKey) -> SignedPreKey {
        SignedPreKey {
            key_id: key.id(),
            public_key: key.key_pair().public(),
            signature: key.signature().to_vec(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyState {
    pub pre_keys: Vec<PreKeyEntity>,
    pub signed_pre_key: SignedPreKey,
    #[serde(with = "serde_public_key")]
    pub identity_key: PublicKey,
}
