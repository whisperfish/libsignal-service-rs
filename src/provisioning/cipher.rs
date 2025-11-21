use std::fmt::{self, Debug};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use bytes::Bytes;
use hmac::{Hmac, Mac};
use libsignal_protocol::{KeyPair, PublicKey};
use prost::Message;
use rand::{CryptoRng, Rng};
use sha2::Sha256;

pub use crate::proto::{ProvisionEnvelope, ProvisionMessage};

use crate::{
    envelope::{CIPHER_KEY_SIZE, IV_LENGTH, IV_OFFSET},
    provisioning::ProvisioningError,
};

enum CipherMode {
    DecryptAndEncrypt(KeyPair),
    EncryptOnly(PublicKey),
}

impl Debug for CipherMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            CipherMode::DecryptAndEncrypt(key_pair) => f
                .debug_tuple("CipherMode::DecryptAndEncrypt")
                .field(&key_pair.public_key)
                .finish(),
            CipherMode::EncryptOnly(public) => f
                .debug_tuple("CipherMode::EncryptOnly")
                .field(&public)
                .finish(),
        }
    }
}

impl CipherMode {
    fn public(&self) -> &PublicKey {
        match self {
            CipherMode::DecryptAndEncrypt(pair) => &pair.public_key,
            CipherMode::EncryptOnly(pub_key) => pub_key,
        }
    }
}

const VERSION: u8 = 1;

#[derive(Debug)]
pub struct ProvisioningCipher {
    key_material: CipherMode,
}

impl ProvisioningCipher {
    pub fn from_public(key: PublicKey) -> Self {
        Self {
            key_material: CipherMode::EncryptOnly(key),
        }
    }

    pub fn from_key_pair(key_pair: KeyPair) -> Self {
        Self {
            key_material: CipherMode::DecryptAndEncrypt(key_pair),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        self.key_material.public()
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        csprng: &mut R,
        msg: ProvisionMessage,
    ) -> Result<ProvisionEnvelope, ProvisioningError> {
        let msg = msg.encode_to_vec();

        let our_key_pair = libsignal_protocol::KeyPair::generate(csprng);
        let agreement = our_key_pair
            .calculate_agreement(self.public_key())
            .map_err(ProvisioningError::invalid_public_key)?;

        let mut shared_secrets = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement)
            .expand(b"TextSecure Provisioning Message", &mut shared_secrets)
            .expect("valid output length");

        let aes_key = &shared_secrets[0..32];
        let mac_key = &shared_secrets[32..];
        let iv: [u8; IV_LENGTH] = csprng.random();

        let cipher = cbc::Encryptor::<Aes256>::new(aes_key.into(), &iv.into());
        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&msg);
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
            .expect("HMAC can take any size key");
        mac.update(&[VERSION]);
        mac.update(&iv);
        mac.update(&ciphertext);
        let mac = mac.finalize().into_bytes();

        let body: Vec<u8> = std::iter::once(VERSION)
            .chain(iv.iter().cloned())
            .chain(ciphertext)
            .chain(mac)
            .collect();

        Ok(ProvisionEnvelope {
            public_key: Some(our_key_pair.public_key.serialize().into()),
            body: Some(body),
        })
    }

    pub fn decrypt(
        &self,
        provision_envelope: ProvisionEnvelope,
    ) -> Result<ProvisionMessage, ProvisioningError> {
        let key_pair = match self.key_material {
            CipherMode::DecryptAndEncrypt(ref key_pair) => key_pair,
            CipherMode::EncryptOnly(_) => {
                return Err(ProvisioningError::EncryptOnlyProvisioningCipher);
            },
        };
        let master_ephemeral = PublicKey::deserialize(
            &provision_envelope.public_key.expect("no public key"),
        )
        .map_err(ProvisioningError::invalid_public_key)?;
        let body = provision_envelope
            .body
            .expect("no body in ProvisionMessage");
        if body[0] != VERSION {
            return Err(ProvisioningError::BadVersionNumber);
        }

        let iv = &body[IV_OFFSET..(IV_LENGTH + IV_OFFSET)];
        let mac = &body[(body.len() - 32)..];
        let cipher_text = &body[16 + 1..(body.len() - CIPHER_KEY_SIZE)];
        let iv_and_cipher_text = &body[0..(body.len() - CIPHER_KEY_SIZE)];
        debug_assert_eq!(iv.len(), IV_LENGTH);
        debug_assert_eq!(mac.len(), 32);

        let agreement = key_pair
            .calculate_agreement(&master_ephemeral)
            .map_err(ProvisioningError::invalid_private_key)?;

        let mut shared_secrets = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &agreement)
            .expand(b"TextSecure Provisioning Message", &mut shared_secrets)
            .expect("valid output length");

        let parts1 = &shared_secrets[0..32];
        let parts2 = &shared_secrets[32..];

        let mut verifier = Hmac::<Sha256>::new_from_slice(parts2)
            .expect("HMAC can take any size key");
        verifier.update(iv_and_cipher_text);
        let our_mac = verifier.finalize().into_bytes();
        debug_assert_eq!(our_mac.len(), mac.len());
        if &our_mac[..32] != mac {
            return Err(ProvisioningError::MismatchedMac);
        }

        // libsignal-service-java uses Pkcs5,
        // but that should not matter.
        // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
        let cipher = cbc::Decryptor::<Aes256>::new(parts1.into(), iv.into());
        let input = cipher
            .decrypt_padded_vec_mut::<Pkcs7>(cipher_text)
            .map_err(ProvisioningError::AesPaddingError)?;

        Ok(prost::Message::decode(Bytes::from(input))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_provisioning_roundtrip() -> anyhow::Result<()> {
        let mut rng = rand::rng();
        let key_pair = KeyPair::generate(&mut rng);
        let cipher = ProvisioningCipher::from_key_pair(key_pair);
        let encrypt_cipher: ProvisioningCipher =
            ProvisioningCipher::from_public(*cipher.public_key());

        assert_eq!(
            cipher.public_key(),
            encrypt_cipher.public_key(),
            "copy public key"
        );

        let msg = ProvisionMessage::default();
        let encrypted = encrypt_cipher.encrypt(&mut rng, msg.clone())?;

        assert!(matches!(
            encrypt_cipher.decrypt(encrypted.clone()),
            Err(ProvisioningError::EncryptOnlyProvisioningCipher)
        ));

        let decrypted = cipher.decrypt(encrypted)?;
        assert_eq!(msg, decrypted);

        Ok(())
    }
}
