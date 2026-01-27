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
    let length = csprng.random_range(0..max_len);
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

pub mod serde_identity_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::IdentityKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        public_key: &IdentityKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let public_key = public_key.serialize();
        serializer.serialize_str(&BASE64_RELAXED.encode(&public_key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IdentityKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        IdentityKey::decode(
            &BASE64_RELAXED
                .decode(String::deserialize(deserializer)?)
                .map_err(serde::de::Error::custom)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub mod serde_optional_identity_key {
    use super::BASE64_RELAXED;
    use base64::prelude::*;
    use libsignal_protocol::IdentityKey;
    use serde::{Deserialize, Deserializer, Serializer};

    use super::serde_identity_key;

    pub fn serialize<S>(
        public_key: &Option<IdentityKey>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match public_key {
            Some(public_key) => {
                serde_identity_key::serialize(public_key, serializer)
            },
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<IdentityKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(public_key) => Ok(Some(
                IdentityKey::decode(
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

pub mod serde_service_id {
    use libsignal_protocol::ServiceId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        service_id: &ServiceId,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&service_id.service_id_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ServiceId, D::Error>
    where
        D: Deserializer<'de>,
    {
        ServiceId::parse_from_service_id_string(&String::deserialize(
            deserializer,
        )?)
        .ok_or_else(|| serde::de::Error::custom("invalid service ID string"))
    }
}

pub mod serde_aci {
    use libsignal_core::Aci;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(aci: &Aci, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&aci.service_id_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Aci, D::Error>
    where
        D: Deserializer<'de>,
    {
        Aci::parse_from_service_id_string(&String::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid ACI string"))
    }
}

pub mod serde_device_id {
    use libsignal_core::DeviceId;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(id: &DeviceId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(u8::from(*id))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DeviceId, D::Error>
    where
        D: Deserializer<'de>,
    {
        DeviceId::try_from(u8::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid device id"))
    }
}

pub mod serde_device_id_vec {
    use libsignal_core::DeviceId;
    use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(
        ids: &Vec<DeviceId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(ids.len()))?;
        for id in ids {
            seq.serialize_element(&u8::from(*id))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<DeviceId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)?
            .into_iter()
            .map(DeviceId::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| serde::de::Error::custom("invalid device id"))
    }
}
