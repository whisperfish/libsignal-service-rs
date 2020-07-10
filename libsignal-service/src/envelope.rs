#![allow(dead_code)] // XXX: remove when all constants on bottom are used.

use prost::Message;

use crate::{
    push_service::ServiceError, utils::serde_optional_base64, ServiceAddress,
};

pub use crate::proto::Envelope;

impl From<EnvelopeEntity> for Envelope {
    fn from(entity: EnvelopeEntity) -> Envelope {
        // XXX: Java also checks whether .source and .source_uuid are
        // not null.
        if entity.source.is_some() && entity.source_device > 0 {
            let address = ServiceAddress {
                uuid: entity.source_uuid.clone(),
                e164: entity.source.clone().unwrap(),
                relay: None,
            };
            Envelope::new_with_source(entity, address)
        } else {
            Envelope::new_from_entity(entity)
        }
    }
}

impl Envelope {
    pub fn decrypt(
        input: &[u8],
        signaling_key: &[u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE],
        is_signaling_key_encrypted: bool,
    ) -> Result<Self, ServiceError> {
        if !is_signaling_key_encrypted {
            Ok(Envelope::decode(input)?)
        } else {
            if input.len() < VERSION_LENGTH
                || input[VERSION_OFFSET] != SUPPORTED_VERSION
            {
                return Err(ServiceError::InvalidFrameError {
                    reason: "Unsupported signaling cryptogram version".into(),
                });
            }

            let aes_key = &signaling_key[..CIPHER_KEY_SIZE];
            let mac_key = &signaling_key[CIPHER_KEY_SIZE..];
            let mac = &input[(input.len() - MAC_SIZE)..];
            let input_for_mac = &input[..(input.len() - MAC_SIZE)];
            let iv = &input[IV_OFFSET..(IV_OFFSET + IV_LENGTH)];
            debug_assert_eq!(mac_key.len(), MAC_KEY_SIZE);
            debug_assert_eq!(aes_key.len(), CIPHER_KEY_SIZE);
            debug_assert_eq!(iv.len(), IV_LENGTH);

            // Verify MAC
            use hmac::{Hmac, Mac, NewMac};
            use sha2::Sha256;
            let mut verifier = Hmac::<Sha256>::new_varkey(mac_key)
                .expect("Hmac can take any size key");
            verifier.update(input_for_mac);
            // XXX: possible timing attack, but we need the bytes for a
            // truncated view...
            let our_mac = verifier.finalize().into_bytes();
            if &our_mac[..MAC_SIZE] != mac {
                return Err(ServiceError::MacError);
            }

            use aes::Aes256;
            // libsignal-service-java uses Pkcs5,
            // but that should not matter.
            // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
            use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
            let cipher = Cbc::<Aes256, Pkcs7>::new_var(&aes_key, iv)
                .expect("initalization of CBC/AES/PKCS7");
            let input = &input[CIPHERTEXT_OFFSET..(input.len() - MAC_SIZE)];
            let input = cipher.decrypt_vec(input).expect("decryption");

            Ok(Envelope::decode(&input as &[u8])?)
        }
    }

    fn new_from_entity(entity: EnvelopeEntity) -> Self {
        Envelope {
            r#type: Some(entity.r#type),
            timestamp: Some(entity.timestamp),
            server_timestamp: Some(entity.server_timestamp),
            server_guid: entity.source_uuid,
            legacy_message: entity.message,
            content: entity.content,
            ..Default::default()
        }
    }

    fn new_with_source(entity: EnvelopeEntity, source: ServiceAddress) -> Self {
        Envelope {
            r#type: Some(entity.r#type),
            source_device: Some(entity.source_device),
            timestamp: Some(entity.timestamp),
            server_timestamp: Some(entity.server_timestamp),
            source_e164: Some(source.e164),
            source_uuid: source.uuid,
            legacy_message: entity.message,
            content: entity.content,
            ..Default::default()
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeEntity {
    pub r#type: i32,
    pub relay: String,
    pub timestamp: u64,
    pub source: Option<String>,
    pub source_uuid: Option<String>,
    pub source_device: u32,
    #[serde(with = "serde_optional_base64")]
    pub message: Option<Vec<u8>>,
    #[serde(with = "serde_optional_base64")]
    pub content: Option<Vec<u8>>,
    pub server_timestamp: u64,
    pub guid: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EnvelopeEntityList {
    pub messages: Vec<EnvelopeEntity>,
}

pub(crate) const SUPPORTED_VERSION: u8 = 1;
pub(crate) const CIPHER_KEY_SIZE: usize = 32;
pub(crate) const MAC_KEY_SIZE: usize = 20;
pub(crate) const MAC_SIZE: usize = 10;

pub(crate) const VERSION_OFFSET: usize = 0;
pub(crate) const VERSION_LENGTH: usize = 1;
pub(crate) const IV_OFFSET: usize = VERSION_OFFSET + VERSION_LENGTH;
pub(crate) const IV_LENGTH: usize = 16;
pub(crate) const CIPHERTEXT_OFFSET: usize = IV_OFFSET + IV_LENGTH;
