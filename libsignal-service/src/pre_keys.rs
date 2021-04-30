use std::convert::TryFrom;

use crate::utils::{serde_base64, serde_public_key};
use libsignal_protocol::{
    error::SignalProtocolError, PreKeyRecord, PublicKey, SignedPreKeyRecord,
};

use serde::{Deserialize, Serialize};

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
            key_id: key.id()?,
            public_key: key.key_pair()?.public_key.serialize().to_vec(),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPreKeyEntity {
    pub key_id: u32,
    #[serde(with = "serde_base64")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
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

impl TryFrom<SignedPreKeyRecord> for SignedPreKey {
    type Error = SignalProtocolError;

    fn try_from(key: SignedPreKeyRecord) -> Result<Self, Self::Error> {
        Ok(SignedPreKey {
            key_id: key.id()?,
            public_key: key.key_pair()?.public_key,
            signature: key.signature()?,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyState {
    pub pre_keys: Vec<PreKeyEntity>,
    pub signed_pre_key: SignedPreKey,
    #[serde(with = "serde_public_key")]
    pub identity_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_resort_key: Option<PreKeyEntity>,
}
