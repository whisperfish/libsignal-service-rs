use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use bytes::Bytes;
use hmac::{Hmac, Mac, NewMac};
use prost::Message;
use rand::Rng;
use sha2::Sha256;

use libsignal_protocol::{
    keys::{KeyPair, PublicKey},
    Context,
};

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

use crate::{
    envelope::{CIPHER_KEY_SIZE, IV_LENGTH, IV_OFFSET},
    provisioning::ProvisioningError,
};

#[derive(Debug)]
enum CipherMode {
    Decrypt(KeyPair),
    Encrypt(PublicKey),
}

impl CipherMode {
    fn public(&self) -> PublicKey {
        match self {
            CipherMode::Decrypt(pair) => pair.public(),
            CipherMode::Encrypt(pub_key) => pub_key.clone(),
        }
    }
}

const VERSION: u8 = 1;

#[derive(Debug)]
pub struct ProvisioningCipher {
    ctx: Context,
    key_material: CipherMode,
}

impl ProvisioningCipher {
    pub fn new(ctx: Context) -> Result<Self, ProvisioningError> {
        let key_pair = libsignal_protocol::generate_key_pair(&ctx)?;
        Ok(Self {
            ctx,
            key_material: CipherMode::Decrypt(key_pair),
        })
    }

    pub fn from_public(ctx: Context, key: PublicKey) -> Self {
        Self {
            ctx,
            key_material: CipherMode::Encrypt(key),
        }
    }

    pub fn from_key_pair(ctx: Context, key_pair: KeyPair) -> Self {
        Self {
            ctx,
            key_material: CipherMode::Decrypt(key_pair),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_material.public()
    }

    pub fn encrypt(
        &self,
        msg: ProvisionMessage,
    ) -> Result<ProvisionEnvelope, ProvisioningError> {
        let msg = {
            let mut encoded = Vec::with_capacity(msg.encoded_len());
            msg.encode(&mut encoded).expect("infallible encoding");
            encoded
        };

        let mut rng = rand::thread_rng();
        let our_key_pair = libsignal_protocol::generate_key_pair(&self.ctx)?;
        let agreement = self
            .public_key()
            .calculate_agreement(&our_key_pair.private())?;
        let hkdf = libsignal_protocol::create_hkdf(&self.ctx, 3)?;

        let shared_secrets = hkdf.derive_secrets(
            64,
            &agreement,
            &[],
            b"TextSecure Provisioning Message",
        )?;

        let aes_key = &shared_secrets[0..32];
        let mac_key = &shared_secrets[32..];
        let iv: [u8; IV_LENGTH] = rng.gen();

        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&aes_key, &iv)
            .expect("initalization of CBC/AES/PKCS7");
        let ciphertext = cipher.encrypt_vec(&msg);
        let mut mac = Hmac::<Sha256>::new_varkey(&mac_key)
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
            public_key: Some(
                our_key_pair.public().to_bytes()?.as_slice().to_vec(),
            ),
            body: Some(body),
        })
    }

    pub fn decrypt(
        &self,
        provision_envelope: ProvisionEnvelope,
    ) -> Result<ProvisionMessage, ProvisioningError> {
        let key_pair = match self.key_material {
            CipherMode::Decrypt(ref key_pair) => key_pair,
            CipherMode::Encrypt(_) => {
                return Err(ProvisioningError::EncryptOnlyProvisioningCipher);
            }
        };
        let master_ephemeral = PublicKey::decode_point(
            &self.ctx,
            &provision_envelope.public_key.expect("no public key"),
        )?;
        let body = provision_envelope
            .body
            .expect("no body in ProvisionMessage");
        if body[0] != VERSION {
            return Err(ProvisioningError::InvalidData {
                reason: "Bad version number".into(),
            });
        }

        let iv = &body[IV_OFFSET..(IV_LENGTH + IV_OFFSET)];
        let mac = &body[(body.len() - 32)..];
        let cipher_text = &body[16 + 1..(body.len() - CIPHER_KEY_SIZE)];
        let iv_and_cipher_text = &body[0..(body.len() - CIPHER_KEY_SIZE)];
        debug_assert_eq!(iv.len(), IV_LENGTH);
        debug_assert_eq!(mac.len(), 32);

        let agreement =
            master_ephemeral.calculate_agreement(&key_pair.private())?;
        let hkdf = libsignal_protocol::create_hkdf(&self.ctx, 3)?;

        let shared_secrets = hkdf.derive_secrets(
            64,
            &agreement,
            &[],
            b"TextSecure Provisioning Message",
        )?;

        let parts1 = &shared_secrets[0..32];
        let parts2 = &shared_secrets[32..];

        let mut verifier = Hmac::<Sha256>::new_varkey(&parts2)
            .expect("HMAC can take any size key");
        verifier.update(&iv_and_cipher_text);
        let our_mac = verifier.finalize().into_bytes();
        debug_assert_eq!(our_mac.len(), mac.len());
        if &our_mac[..32] != mac {
            return Err(ProvisioningError::InvalidData {
                reason: "wrong MAC".into(),
            });
        }

        // libsignal-service-java uses Pkcs5,
        // but that should not matter.
        // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&parts1, &iv)
            .expect("initalization of CBC/AES/PKCS7");
        let input = cipher.decrypt_vec(cipher_text).map_err(|e| {
            ProvisioningError::InvalidData {
                reason: format!("CBC/Padding error: {:?}", e),
            }
        })?;

        Ok(prost::Message::decode(Bytes::from(input))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_provisioning_roundtrip() {
        let ctx = Context::default();
        let cipher = ProvisioningCipher::new(ctx.clone()).unwrap();
        let encrypt_cipher =
            ProvisioningCipher::from_public(ctx.clone(), cipher.public_key());

        assert_eq!(
            cipher.public_key(),
            encrypt_cipher.public_key(),
            "copy public key"
        );

        let msg = ProvisionMessage::default();
        let encrypted = encrypt_cipher.encrypt(msg.clone()).unwrap();

        assert!(matches!(
            encrypt_cipher.decrypt(encrypted.clone()),
            Err(ProvisioningError::EncryptOnlyProvisioningCipher)
        ));

        let decrypted = cipher.decrypt(encrypted).expect("decryptability");
        assert_eq!(msg, decrypted);
    }
}
