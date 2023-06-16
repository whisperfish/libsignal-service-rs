pub use crate::attachment_cipher::{
    decrypt_in_place, encrypt_in_place, AttachmentCipherError,
};

pub fn derive_key(ikm: &[u8]) -> Result<[u8; 64], AttachmentCipherError> {
    let mut key = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, ikm)
        .expand(b"Sticker Pack", &mut key)
        .expect("valid output length");
    Ok(key)
}
