use std::convert::TryInto;

use aes_gcm::{aead::Aead, AeadCore, AeadInPlace, Aes256Gcm, KeyInit};
use rand::{rand_core, CryptoRng, RngCore};
use zkgroup::profiles::ProfileKey;

use crate::{
    profile_name::ProfileName, websocket::profile::SignalServiceProfile,
    Profile,
};

/// Encrypt and decrypt a [`ProfileName`] and other profile information.
///
/// # Example
///
/// ```rust
/// # use libsignal_service::{profile_name::ProfileName, profile_cipher::ProfileCipher};
/// # use zkgroup::profiles::ProfileKey;
/// # use rand::Rng;
/// # let mut rng = rand::rng();
/// # let some_randomness = rng.random();
/// let profile_key = ProfileKey::generate(some_randomness);
/// let name = ProfileName::<&str> {
///     given_name: "Bill",
///     family_name: None,
/// };
/// let cipher = ProfileCipher::new(profile_key);
/// let encrypted = cipher.encrypt_name(&name, &mut rng).unwrap();
/// let decrypted = cipher.decrypt_name(&encrypted).unwrap().unwrap();
/// assert_eq!(decrypted.as_ref(), name);
/// ```
pub struct ProfileCipher {
    profile_key: ProfileKey,
}

const NAME_PADDED_LENGTH_1: usize = 53;
const NAME_PADDED_LENGTH_2: usize = 257;
const NAME_PADDING_BRACKETS: &[usize] =
    &[NAME_PADDED_LENGTH_1, NAME_PADDED_LENGTH_2];

const ABOUT_PADDED_LENGTH_1: usize = 128;
const ABOUT_PADDED_LENGTH_2: usize = 254;
const ABOUT_PADDED_LENGTH_3: usize = 512;
const ABOUT_PADDING_BRACKETS: &[usize] = &[
    ABOUT_PADDED_LENGTH_1,
    ABOUT_PADDED_LENGTH_2,
    ABOUT_PADDED_LENGTH_3,
];

const EMOJI_PADDED_LENGTH: usize = 32;

#[derive(thiserror::Error, Debug)]
pub enum ProfileCipherError {
    #[error("Encryption error")]
    EncryptionError,
    #[error("UTF-8 decode error {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("Input name too long")]
    InputTooLong,
}

fn pad_plaintext(
    bytes: &mut Vec<u8>,
    brackets: &[usize],
) -> Result<usize, ProfileCipherError> {
    let len = brackets
        .iter()
        .find(|x| **x >= bytes.len())
        .ok_or(ProfileCipherError::InputTooLong)?;
    let len: usize = *len;

    bytes.resize(len, 0);
    assert!(brackets.contains(&bytes.len()));

    Ok(len)
}

impl ProfileCipher {
    pub fn new(profile_key: ProfileKey) -> Self {
        Self { profile_key }
    }

    pub fn into_inner(self) -> ProfileKey {
        self.profile_key
    }

    fn pad_and_encrypt<R: RngCore + CryptoRng>(
        &self,
        mut bytes: Vec<u8>,
        padding_brackets: &[usize],
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let _len = pad_plaintext(&mut bytes, padding_brackets)?;

        let csprng = Rng06Shiv(csprng);

        let cipher = Aes256Gcm::new(&self.profile_key.get_bytes().into());
        let nonce = Aes256Gcm::generate_nonce(csprng);

        cipher
            .encrypt_in_place(&nonce, b"", &mut bytes)
            .map_err(|_| ProfileCipherError::EncryptionError)?;

        let mut concat = Vec::with_capacity(nonce.len() + bytes.len());
        concat.extend_from_slice(&nonce);
        concat.extend_from_slice(&bytes);
        Ok(concat)
    }

    fn decrypt_and_unpad(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = bytes.as_ref();
        let nonce: [u8; 12] = bytes[0..12]
            .try_into()
            .expect("fixed length nonce material");
        let cipher = Aes256Gcm::new(&self.profile_key.get_bytes().into());

        let mut plaintext = cipher
            .decrypt(&nonce.into(), &bytes[12..])
            .map_err(|_| ProfileCipherError::EncryptionError)?;

        // Unpad
        let len = plaintext
            .iter()
            // Search the first non-0 char...
            .rposition(|x| *x != 0)
            // ...and strip until right after.
            .map(|x| x + 1)
            // If it's all zeroes, the string is 0-length.
            .unwrap_or(0);
        plaintext.truncate(len);
        Ok(plaintext)
    }

    pub fn decrypt(
        &self,
        encrypted_profile: SignalServiceProfile,
    ) -> Result<Profile, ProfileCipherError> {
        let name = encrypted_profile
            .name
            .as_ref()
            .map(|data| self.decrypt_name(data))
            .transpose()?
            .flatten();
        let about = encrypted_profile
            .about
            .as_ref()
            .map(|data| self.decrypt_about(data))
            .transpose()?;
        let about_emoji = encrypted_profile
            .about_emoji
            .as_ref()
            .map(|data| self.decrypt_emoji(data))
            .transpose()?;

        Ok(Profile {
            name,
            about,
            about_emoji,
            avatar: encrypted_profile.avatar,
            unrestricted_unidentified_access: encrypted_profile
                .unrestricted_unidentified_access,
        })
    }

    pub fn decrypt_avatar(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<u8>, ProfileCipherError> {
        self.decrypt_and_unpad(bytes)
    }

    pub fn encrypt_name<'inp, R: RngCore + CryptoRng>(
        &self,
        name: impl std::borrow::Borrow<ProfileName<&'inp str>>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let name = name.borrow();
        let bytes = name.serialize();
        self.pad_and_encrypt(bytes, NAME_PADDING_BRACKETS, csprng)
    }

    pub fn decrypt_name(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Option<ProfileName<String>>, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        Ok(ProfileName::<String>::deserialize(&plaintext)?)
    }

    pub fn encrypt_about<R: RngCore + CryptoRng>(
        &self,
        about: String,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = about.into_bytes();
        self.pad_and_encrypt(bytes, ABOUT_PADDING_BRACKETS, csprng)
    }

    pub fn decrypt_about(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<String, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        // XXX This re-allocates.
        Ok(std::str::from_utf8(&plaintext)?.into())
    }

    pub fn encrypt_emoji<R: RngCore + CryptoRng>(
        &self,
        emoji: String,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ProfileCipherError> {
        let bytes = emoji.into_bytes();
        self.pad_and_encrypt(bytes, &[EMOJI_PADDED_LENGTH], csprng)
    }

    pub fn decrypt_emoji(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<String, ProfileCipherError> {
        let bytes = bytes.as_ref();

        let plaintext = self.decrypt_and_unpad(bytes)?;

        // XXX This re-allocates.
        Ok(std::str::from_utf8(&plaintext)?.into())
    }
}

struct Rng06Shiv<'a, T>(&'a mut T);

impl<T: rand_core::RngCore> rand_core_06::RngCore for Rng06Shiv<'_, T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<T: rand_core::CryptoRng> rand_core_06::CryptoRng for Rng06Shiv<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_name::ProfileName;
    use rand::Rng;
    use zkgroup::profiles::ProfileKey;

    #[test]
    fn roundtrip_name() {
        let names = [
            "Me and my guitar", // shorter that 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", // one shorter than 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzx", // exactly 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxf", // one more than 53
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzxfoobar", // a bit more than 53
        ];

        // Test the test cases
        assert_eq!(names[1].len(), NAME_PADDED_LENGTH_1 - 1);
        assert_eq!(names[2].len(), NAME_PADDED_LENGTH_1);
        assert_eq!(names[3].len(), NAME_PADDED_LENGTH_1 + 1);

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);
        for name in &names {
            let profile_name = ProfileName::<&str> {
                given_name: name,
                family_name: None,
            };
            assert_eq!(profile_name.serialize().len(), name.len());
            let encrypted =
                cipher.encrypt_name(&profile_name, &mut rng).unwrap();
            let decrypted = cipher.decrypt_name(encrypted).unwrap().unwrap();

            assert_eq!(decrypted.as_ref(), profile_name);
            assert_eq!(decrypted.serialize(), profile_name.serialize());
            assert_eq!(&decrypted.given_name, name);
        }
    }

    #[test]
    fn roundtrip_about() {
        let abouts = [
            "Me and my guitar", // shorter that 53
        ];

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        for &about in &abouts {
            let encrypted =
                cipher.encrypt_about(about.into(), &mut rng).unwrap();
            let decrypted = cipher.decrypt_about(encrypted).unwrap();

            assert_eq!(decrypted, about);
        }
    }

    #[test]
    fn roundtrip_emoji() {
        let emojii = ["❤️", "💩", "🤣", "😲", "🐠"];

        let mut rng = rand::rng();
        let some_randomness = rng.random();
        let profile_key = ProfileKey::generate(some_randomness);
        let cipher = ProfileCipher::new(profile_key);

        for &emoji in &emojii {
            let encrypted =
                cipher.encrypt_emoji(emoji.into(), &mut rng).unwrap();
            let decrypted = cipher.decrypt_emoji(encrypted).unwrap();

            assert_eq!(decrypted, emoji);
        }
    }
}
