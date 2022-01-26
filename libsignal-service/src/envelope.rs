#![allow(dead_code)] // XXX: remove when all constants on bottom are used.

use prost::Message;
use uuid::Uuid;

use crate::{
    configuration::SignalingKey, push_service::ServiceError,
    utils::serde_optional_base64, ParseServiceAddressError, ServiceAddress,
};

pub use crate::proto::Envelope;

#[derive(thiserror::Error, Debug, Clone)]
pub enum EnvelopeParseError {
    #[error("Supplied phone number could not be parsed in E164 format")]
    InvalidPhoneNumber(#[from] phonenumber::ParseError),

    #[error("Supplied uuid could not be parsed")]
    InvalidUuidError(#[from] uuid::Error),

    #[error("Envelope with neither Uuid or E164")]
    NoSenderError,
}

impl std::convert::TryFrom<EnvelopeEntity> for Envelope {
    type Error = EnvelopeParseError;

    fn try_from(
        entity: EnvelopeEntity,
    ) -> Result<Envelope, EnvelopeParseError> {
        use ParseServiceAddressError::*;
        if entity.source.is_none() && entity.source_uuid.is_none() {
            return Err(EnvelopeParseError::NoSenderError);
        }

        // XXX: throwing allocations like it's Java.
        let source = ServiceAddress::parse(
            entity.source.as_deref(),
            entity.source_uuid.as_deref(),
        );
        match source {
            // Valid source
            Ok(source) if entity.source_device > 0 => {
                Ok(Envelope::new_with_source(entity, source))
            },
            // No source
            Ok(_) | Err(NoSenderError) => Ok(Envelope::new_from_entity(entity)),
            // Source specified, but unparsable
            Err(InvalidPhoneNumber(e)) => {
                Err(EnvelopeParseError::InvalidPhoneNumber(e))
            },
            Err(InvalidUuidError(e)) => {
                Err(EnvelopeParseError::InvalidUuidError(e))
            },
        }
    }
}

impl Envelope {
    pub fn decrypt(
        input: &[u8],
        signaling_key: &SignalingKey,
        is_signaling_key_encrypted: bool,
    ) -> Result<Self, ServiceError> {
        if !is_signaling_key_encrypted {
            log::trace!("Envelope::decrypt: not encrypted");
            Ok(Envelope::decode(input)?)
        } else {
            log::trace!("Envelope::decrypt: decrypting");
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
            let mut verifier = Hmac::<Sha256>::new_from_slice(mac_key)
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
            let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(aes_key, iv)
                .expect("initalization of CBC/AES/PKCS7");
            let input = &input[CIPHERTEXT_OFFSET..(input.len() - MAC_SIZE)];
            let input = cipher.decrypt_vec(input).expect("decryption");

            log::trace!("Envelope::decrypt: decrypted, decoding");

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
            source_e164: source.e164(),
            source_uuid: source.uuid.as_ref().map(|s| s.to_string()),
            legacy_message: entity.message,
            content: entity.content,
            ..Default::default()
        }
    }

    pub fn is_unidentified_sender(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::UnidentifiedSender
    }

    pub fn is_prekey_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::PrekeyBundle
    }

    pub fn is_receipt(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::Receipt
    }

    pub fn is_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::Ciphertext
    }

    pub fn source_address(&self) -> ServiceAddress {
        let phonenumber = self
            .source_e164
            .as_ref()
            .map(|s| phonenumber::parse(None, s))
            .transpose()
            .expect("valid e164 checked in constructor");

        let uuid = self
            .source_uuid
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .expect("valid e164 checked in constructor");
        ServiceAddress {
            phonenumber,
            uuid,
            relay: self.relay.clone(),
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
    #[serde(default, with = "serde_optional_base64")]
    pub message: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_envelope() {
        // This is a real message, reencrypted with the zero-key.
        let body = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79, 32, 12, 100,
            26, 157, 130, 210, 254, 174, 87, 45, 238, 126, 68, 39, 188, 171,
            156, 16, 10, 138, 233, 73, 202, 52, 125, 102, 121, 182, 71, 148, 8,
            3, 134, 149, 154, 67, 116, 40, 146, 253, 242, 196, 139, 203, 14,
            174, 254, 78, 27, 47, 108, 60, 202, 60, 42, 210, 242, 58, 13, 185,
            67, 147, 166, 191, 71, 164, 128, 81, 177, 199, 147, 252, 162, 229,
            143, 98, 141, 222, 46, 83, 109, 82, 196, 109, 161, 40, 108, 207,
            82, 53, 162, 205, 171, 33, 140, 5, 74, 76, 150, 22, 122, 176, 189,
            228, 176, 234, 176, 13, 118, 181, 134, 35, 133, 164, 160, 205, 176,
            32, 188, 185, 166, 73, 24, 164, 20, 187, 2, 226, 186, 238, 98, 57,
            51, 76, 156, 83, 113, 72, 184, 50, 220, 49, 138, 46, 36, 4, 49,
            215, 66, 173, 58, 139, 187, 6, 252, 97, 191, 69, 246, 82, 48, 177,
            11, 149, 168, 93, 15, 170, 125, 131, 101, 103, 253, 177, 165, 71,
            85, 219, 207, 106, 12, 58, 47, 159, 33, 243, 107, 6, 117, 141, 209,
            115, 207, 19, 236, 137, 195, 230, 167, 225, 172, 99, 204, 113, 125,
            69, 125, 97, 252, 90, 248, 198, 175, 240, 187, 246, 164, 220, 102,
            7, 224, 124, 28, 170, 6, 4, 137, 155, 233, 85, 125, 93, 119, 97,
            183, 114, 193, 10, 184, 191, 202, 109, 97, 116, 194, 152, 40, 46,
            202, 49, 195, 138, 14, 2, 255, 44, 107, 160, 45, 150, 6, 78, 145,
            99,
        ];

        let signaling_key = [0u8; 52];
        let _ = Envelope::decrypt(&body, &signaling_key, true).unwrap();
    }
}
