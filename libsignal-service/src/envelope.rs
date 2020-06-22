use crate::{
    utils::{serde_base64, serde_optional_base64},
    ServiceAddress,
};

pub struct Envelope {
    inner: crate::proto::Envelope,
}

impl From<EnvelopeEntity> for Envelope {
    fn from(entity: EnvelopeEntity) -> Envelope {
        // XXX: Java also checks whether .source and .source_uuid are
        // not null.
        if entity.source.is_some() && entity.source_device > 0 {
            let address = ServiceAddress {
                uuid: entity.source_uuid.clone(),
                e164: entity.source.clone().unwrap(),
                relay: None,
            };
            Envelope::new_with_source(entity, address)
        } else {
            Envelope::new_from_entity(entity)
        }
    }
}

impl Envelope {
    fn new_from_entity(entity: EnvelopeEntity) -> Self {
        Envelope {
            inner: crate::proto::Envelope {
                r#type: Some(entity.r#type),
                timestamp: Some(entity.timestamp),
                server_timestamp: Some(entity.server_timestamp),
                server_guid: entity.source_uuid,
                legacy_message: entity.message,
                content: entity.content,
                ..Default::default()
            },
        }
    }

    fn new_with_source(entity: EnvelopeEntity, source: ServiceAddress) -> Self {
        Envelope {
            inner: crate::proto::Envelope {
                r#type: Some(entity.r#type),
                source_device: Some(entity.source_device),
                timestamp: Some(entity.timestamp),
                server_timestamp: Some(entity.server_timestamp),
                source_e164: Some(source.e164),
                source_uuid: source.uuid,
                legacy_message: entity.message,
                content: entity.content,
                ..Default::default()
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeEntity {
    pub r#type: i32,
    pub relay: String,
    pub timestamp: u64,
    pub source: Option<String>,
    pub source_uuid: Option<String>,
    pub source_device: u32,
    #[serde(with = "serde_optional_base64")]
    pub message: Option<Vec<u8>>,
    #[serde(with = "serde_optional_base64")]
    pub content: Option<Vec<u8>>,
    pub server_timestamp: u64,
    pub guid: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EnvelopeEntityList {
    pub messages: Vec<EnvelopeEntity>,
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
