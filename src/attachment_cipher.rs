use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AttachmentCipherError {
    #[error("MAC verification error")]
    MacError,
    #[error("Padding verification error")]
    PaddingError,
}

/// Encrypts an attachment in place, given the key material.
///
/// The Vec will be reused when it has enough space to house the MAC,
/// otherwise reallocation might happen.
#[tracing::instrument(skip(iv, key, plaintext))]
pub fn encrypt_in_place(iv: [u8; 16], key: [u8; 64], plaintext: &mut Vec<u8>) {
    let aes_half = &key[..32];
    let mac_half = &key[32..];

    let plaintext_len = plaintext.len();
    plaintext.reserve(plaintext.len() + 16 + 16);

    // Prepend IV
    plaintext.extend(&[0u8; 16]);
    plaintext.copy_within(..plaintext_len, 16);
    plaintext[0..16].copy_from_slice(&iv);

    // Pad with zeroes for padding
    plaintext.extend(&[0u8; 16]);

    let cipher = Aes256CbcEnc::new(aes_half.into(), &iv.into());

    let buffer = plaintext;
    let ciphertext_slice = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer[16..], plaintext_len)
        .expect("encrypted ciphertext");
    let ciphertext_len = ciphertext_slice.len();
    // Correct length for padding
    buffer.truncate(16 + ciphertext_len);

    // Compute and append MAC
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_half)
        .expect("fixed length key material");
    mac.update(buffer);
    buffer.extend(mac.finalize().into_bytes());
}

/// Decrypts an attachment in place, given the key material.
///
/// On error, ciphertext is not changed.
#[tracing::instrument(skip(key, ciphertext))]
pub fn decrypt_in_place(
    key: [u8; 64],
    ciphertext: &mut Vec<u8>,
) -> Result<(), AttachmentCipherError> {
    let aes_half = &key[..32];
    let mac_half = &key[32..];

    let ciphertext_len = ciphertext.len();

    let (buffer, their_mac) = ciphertext.split_at_mut(ciphertext_len - 32);

    // Compute and append MAC
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_half)
        .expect("fixed length key material");
    mac.update(buffer);
    mac.verify_slice(their_mac)
        .map_err(|_| AttachmentCipherError::MacError)?;

    let (iv, buffer) = buffer.split_at_mut(16);

    let cipher = Aes256CbcDec::new(aes_half.into(), (&*iv).into());

    let plaintext_slice = cipher
        .decrypt_padded_mut::<Pkcs7>(buffer)
        .map_err(|_| AttachmentCipherError::PaddingError)?;

    let plaintext_len = plaintext_slice.len();

    // Get rid of IV and MAC
    ciphertext.copy_within(16..(plaintext_len + 16), 0);
    ciphertext.truncate(plaintext_len);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::prelude::*;

    #[test]
    fn attachment_encrypt_decrypt() -> Result<(), AttachmentCipherError> {
        let mut key = [0u8; 64];
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut iv);

        let plaintext = b"Peter Parker";
        let mut buf = Vec::from(plaintext as &[u8]);
        encrypt_in_place(iv, key, &mut buf);
        assert_ne!(&buf, &plaintext);
        decrypt_in_place(key, &mut buf)?;
        assert_eq!(&buf, &plaintext);
        Ok(())
    }

    #[test]
    fn attachment_encrypt_decrypt_empty() -> Result<(), AttachmentCipherError> {
        let mut key = [0u8; 64];
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut iv);
        let plaintext = b"";
        let mut buf = Vec::from(plaintext as &[u8]);
        encrypt_in_place(iv, key, &mut buf);
        assert_ne!(&buf, &plaintext);
        decrypt_in_place(key, &mut buf)?;
        assert_eq!(&buf, &plaintext);
        Ok(())
    }

    #[test]
    fn attachment_encrypt_decrypt_bad_key() {
        let mut key = [0u8; 64];
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut iv);
        let plaintext = b"Peter Parker";
        let mut buf = Vec::from(plaintext as &[u8]);
        encrypt_in_place(iv, key, &mut buf);

        // Generate bad key
        rand::rng().fill_bytes(&mut key);
        assert_eq!(
            decrypt_in_place(key, &mut buf).unwrap_err(),
            AttachmentCipherError::MacError
        );
        assert_ne!(&buf, &plaintext);
    }

    #[test]
    fn know_answer_test_attachment() -> Result<(), AttachmentCipherError> {
        let mut ciphertext = include!("kat.bin.rs");
        let key_material = [
            52, 102, 97, 87, 153, 192, 64, 116, 93, 96, 57, 110, 6, 197, 208,
            85, 49, 249, 154, 137, 116, 124, 112, 107, 8, 158, 48, 4, 8, 66,
            173, 5, 28, 16, 199, 226, 234, 38, 69, 167, 163, 34, 107, 164, 15,
            118, 101, 146, 34, 213, 85, 164, 110, 83, 129, 245, 62, 44, 158,
            78, 205, 62, 153, 108,
        ];

        decrypt_in_place(key_material, &mut ciphertext)?;
        // This 32 is given by the AttachmentPointer
        ciphertext.truncate(32);
        assert_eq!(ciphertext, b"test for libsignal-service-rust\n");
        Ok(())
    }
}
