// Signal sometimes adds padding, sometimes it does not.
// This requires a custom decoding engine.
// This engine is as general as possible.
pub const BASE64_RELAXED: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(
                base64::engine::DecodePaddingMode::Indifferent,
            ),
    );

pub fn random_length_padding<R: rand::Rng + rand::CryptoRng>(
    csprng: &mut R,
    max_len: usize,
) -> Vec<u8> {
    let length = csprng.gen_range(0..max_len);
    let mut padding = vec![0u8; length];
    csprng.fill_bytes(&mut padding);
    padding
}

pub mod serde_base64 {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_RELAXED.encode(bytes.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            BASE64_RELAXED
                .decode(string)
                .map_err(|err| Error::custom(err.to_string()))
        })
    }
}

pub mod serde_optional_base64 {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::serde_base64;

    pub fn serialize<T, S>(
        bytes: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        match bytes {
            Some(bytes) => serde_base64::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        match Option::<String>::deserialize(deserializer)? {
            Some(s) => BASE64_RELAXED
                .decode(s)
                .map_err(|err| Error::custom(err.to_string()))
                .map(Some),
            None => Ok(None),
        }
    }
}

pub mod serde_public_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        public_key: &PublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let public_key = public_key.serialize();
        serializer.serialize_str(&BASE64_RELAXED.encode(&public_key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKey::deserialize(
            &BASE64_RELAXED
                .decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub mod serde_optional_public_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::serde_public_key;

    pub fn serialize<S>(
        public_key: &Option<PublicKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match public_key {
            Some(public_key) => {
                serde_public_key::serialize(public_key, serializer)
            },
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<PublicKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(public_key) => Ok(Some(
                PublicKey::deserialize(
                    &BASE64_RELAXED
                        .decode(public_key)
                        .map_err(serde::de::Error::custom)?,
                )
                .map_err(serde::de::Error::custom)?,
            )),
            None => Ok(None),
        }
    }
}

pub mod serde_private_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::PrivateKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        public_key: &PrivateKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let public_key = public_key.serialize();
        serializer.serialize_str(&BASE64_RELAXED.encode(public_key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        PrivateKey::deserialize(
            &BASE64_RELAXED
                .decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub mod serde_optional_private_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::PrivateKey;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::serde_private_key;

    pub fn serialize<S>(
        private_key: &Option<PrivateKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match private_key {
            Some(private_key) => {
                serde_private_key::serialize(private_key, serializer)
            },
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<PrivateKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(private_key) => Ok(Some(
                PrivateKey::deserialize(
                    &BASE64_RELAXED
                        .decode(private_key)
                        .map_err(serde::de::Error::custom)?,
                )
                .map_err(serde::de::Error::custom)?,
            )),
            None => Ok(None),
        }
    }
}

pub mod serde_signaling_key {
    use std::convert::TryInto;

    use super::BASE64_RELAXED;
    use crate::configuration::SignalingKey;
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        signaling_key: &SignalingKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_RELAXED.encode(signaling_key))
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<SignalingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        BASE64_RELAXED
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|buf: Vec<u8>| {
                serde::de::Error::invalid_length(
                    buf.len(),
                    &"invalid signaling key length",
                )
            })
    }
}

pub mod serde_phone_number {
    use phonenumber::PhoneNumber;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        phone_number: &PhoneNumber,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&phone_number.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PhoneNumber, D::Error>
    where
        D: Deserializer<'de>,
    {
        phonenumber::parse(None, String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
