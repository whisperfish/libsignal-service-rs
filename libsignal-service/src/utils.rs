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
