use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use libsignal_protocol::ServiceId;
use prost::Message;

use crate::{configuration::SignalingKey, push_service::ServiceError};

pub use crate::proto::Envelope;

impl Envelope {
    #[tracing::instrument(skip(input, signaling_key), fields(signaling_key_present = signaling_key.is_some(), input_size = input.len()))]
    pub fn decrypt(
        input: &[u8],
        signaling_key: Option<&SignalingKey>,
        is_signaling_key_encrypted: bool,
    ) -> Result<Self, ServiceError> {
        if !is_signaling_key_encrypted {
            tracing::trace!("Envelope::decrypt: not encrypted");
            Ok(Envelope::decode(input)?)
        } else {
            let signaling_key = signaling_key
                .expect("signaling_key required to decrypt envelopes");
            tracing::trace!("Envelope::decrypt: decrypting");
            if input.len() < VERSION_LENGTH
                || input[VERSION_OFFSET] != SUPPORTED_VERSION
            {
                return Err(ServiceError::InvalidFrame {
                    reason: "unsupported signaling cryptogram version",
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
            use hmac::{Hmac, Mac};
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

            // libsignal-service-java uses Pkcs5,
            // but that should not matter.
            // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
            let cipher =
                cbc::Decryptor::<aes::Aes256>::new(aes_key.into(), iv.into());
            let input = &input[CIPHERTEXT_OFFSET..(input.len() - MAC_SIZE)];
            let input = cipher
                .decrypt_padded_vec_mut::<Pkcs7>(input)
                .expect("decryption");

            tracing::trace!("Envelope::decrypt: decrypted, decoding");

            Ok(Envelope::decode(&input as &[u8])?)
        }
    }

    pub fn is_unidentified_sender(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::UnidentifiedSender
    }

    pub fn is_prekey_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::PrekeyBundle
    }

    pub fn is_receipt(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::ServerDeliveryReceipt
    }

    pub fn is_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::Ciphertext
    }

    pub fn is_urgent(&self) -> bool {
        // SignalServiceEnvelopeEntity: return urgent == null || urgent;
        self.urgent.unwrap_or(true)
    }

    pub fn is_story(&self) -> bool {
        self.story.unwrap_or(false)
    }

    pub fn source_address(&self) -> ServiceId {
        match self.source_service_id.as_deref() {
            Some(service_id) => {
                ServiceId::parse_from_service_id_string(service_id)
                    .expect("invalid source ProtocolAddress UUID or prefix")
            },
            None => panic!("source_service_id is set"),
        }
    }

    pub fn destination_address(&self) -> ServiceId {
        match self.destination_service_id.as_deref() {
            Some(service_id) => ServiceId::parse_from_service_id_string(
                service_id,
            )
            .expect("invalid destination ProtocolAddress UUID or prefix"),
            None => panic!("destination_address is set"),
        }
    }
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
        let envelope =
            Envelope::decrypt(&body, Some(&signaling_key), true).unwrap();
        assert_eq!(envelope.server_timestamp(), 1594373582421);
        assert_eq!(envelope.timestamp(), 1594373580977);
        assert_eq!(
            envelope.content(),
            [
                51, 10, 33, 5, 239, 254, 183, 191, 204, 223, 85, 150, 43, 192,
                240, 57, 46, 189, 153, 7, 48, 17, 9, 166, 185, 157, 205, 181,
                66, 235, 99, 221, 114, 58, 187, 117, 16, 76, 24, 0, 34, 160, 1,
                85, 61, 73, 83, 99, 213, 160, 109, 122, 125, 204, 137, 178,
                237, 146, 87, 183, 107, 33, 213, 234, 64, 152, 132, 122, 173,
                25, 33, 4, 65, 20, 134, 117, 62, 116, 80, 151, 18, 132, 187,
                101, 235, 208, 74, 78, 214, 66, 59, 71, 171, 124, 167, 217,
                157, 36, 194, 156, 12, 50, 239, 185, 230, 253, 38, 107, 106,
                149, 194, 39, 214, 35, 245, 58, 216, 250, 225, 150, 170, 26,
                241, 153, 133, 173, 197, 194, 27, 127, 56, 77, 119, 242, 26,
                252, 168, 61, 221, 44, 76, 128, 69, 27, 203, 6, 173, 193, 179,
                69, 27, 243, 36, 185, 181, 157, 41, 23, 72, 113, 40, 209, 46,
                189, 63, 167, 156, 148, 118, 76, 153, 91, 40, 179, 180, 245,
                193, 123, 180, 47, 115, 220, 191, 148, 245, 116, 32, 194, 232,
                55, 13, 0, 217, 52, 116, 21, 48, 244, 17, 222, 26, 240, 31,
                236, 199, 237, 94, 255, 93, 137, 192,
            ]
        );
    }
}
