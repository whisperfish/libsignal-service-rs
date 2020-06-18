pub struct Envelope {
    inner: crate::proto::Envelope,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnvelopeEntity {
    pub r#type: i32,
    pub relay: String,
    pub timestamp: i64,
    pub source: String,
    pub source_uuid: String,
    pub source_device: i32,
    pub message: Vec<u8>,
    pub content: Vec<u8>,
    pub server_timestamp: i64,
    pub guid: String,
}

const SUPPORTED_VERSION: usize = 1;
const CIPHER_KEY_SIZE: usize = 32;
const MAC_KEY_SIZE: usize = 20;
const MAC_SIZE: usize = 10;

const VERSION_OFFSET: usize = 0;
const VERSION_LENGTH: usize = 1;
const IV_OFFSET: usize = VERSION_OFFSET + VERSION_LENGTH;
const IV_LENGTH: usize = 16;
const CIPHERTEXT_OFFSET: usize = IV_OFFSET + IV_LENGTH;
