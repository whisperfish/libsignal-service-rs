pub mod serde_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(bytes.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| {
            base64::decode(&string)
                .map_err(|err| Error::custom(err.to_string()))
        })
    }
}

pub mod serde_optional_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(
        bytes: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]>,
        S: Serializer,
    {
        match bytes {
            Some(bytes) => {
                serializer.serialize_str(&base64::encode(bytes.as_ref()))
            },
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
            Some(s) => base64::decode(&s)
                .map_err(|err| Error::custom(err.to_string()))
                .map(Some),
            None => Ok(None),
        }
    }
}

pub mod serde_public_key {
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
        serializer.serialize_str(&base64::encode(&public_key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKey::deserialize(
            &base64::decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub mod serde_private_key {
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
        serializer.serialize_str(&base64::encode(&public_key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        PrivateKey::deserialize(
            &base64::decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub mod serde_signaling_key {
    use std::convert::TryInto;

    use crate::configuration::SignalingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        signaling_key: &SignalingKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(signaling_key))
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<SignalingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        base64::decode(String::deserialize(deserializer)?)
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
