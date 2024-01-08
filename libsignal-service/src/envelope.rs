use std::convert::{TryFrom, TryInto};

use uuid::Uuid;

use crate::{
    utils::serde_optional_base64, ParseServiceAddressError, ServiceAddress,
};

pub use crate::proto::Envelope;

impl TryFrom<EnvelopeEntity> for Envelope {
    type Error = ParseServiceAddressError;

    fn try_from(entity: EnvelopeEntity) -> Result<Self, Self::Error> {
        match entity.source_uuid.as_deref() {
            Some(uuid) => {
                let address = uuid.try_into()?;
                Ok(Envelope::new_with_source(entity, address))
            },
            None => Ok(Envelope::new_from_entity(entity)),
        }
    }
}

impl Envelope {
    fn new_from_entity(entity: EnvelopeEntity) -> Self {
        Envelope {
            r#type: Some(entity.r#type),
            timestamp: Some(entity.timestamp),
            server_timestamp: Some(entity.server_timestamp),
            server_guid: entity.source_uuid,
            content: entity.content,
            ..Default::default()
        }
    }

    fn new_with_source(entity: EnvelopeEntity, source: ServiceAddress) -> Self {
        Envelope {
            r#type: Some(entity.r#type),
            source_device: Some(entity.source_device),
            timestamp: Some(entity.timestamp),
            server_timestamp: Some(entity.server_timestamp),
            source_service_id: Some(source.uuid.to_string()),
            content: entity.content,
            ..Default::default()
        }
    }

    pub fn is_unidentified_sender(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::UnidentifiedSender
    }

    pub fn is_prekey_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::PrekeyBundle
    }

    pub fn is_receipt(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::Receipt
    }

    pub fn is_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::Ciphertext
    }

    pub fn is_urgent(&self) -> bool {
        // SignalServiceEnvelopeEntity: return urgent == null || urgent;
        self.urgent.unwrap_or(true)
    }

    pub fn is_story(&self) -> bool {
        self.story.unwrap_or(false)
    }

    pub fn source_address(&self) -> ServiceAddress {
        let uuid = self
            .source_service_id
            .as_deref()
            .and_then(|u| Uuid::parse_str(u).ok())
            .expect("valid uuid checked in constructor");

        ServiceAddress { uuid }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeEntity {
    pub r#type: i32,
    pub timestamp: u64,
    pub source: Option<String>,
    pub source_uuid: Option<String>,
    pub source_device: u32,
    #[serde(default)]
    pub destination_uuid: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub content: Option<Vec<u8>>,
    pub server_timestamp: u64,
    pub guid: String,
    #[serde(default = "default_true")]
    pub urgent: bool,
    #[serde(default)]
    pub story: bool,
    #[serde(default, with = "serde_optional_base64")]
    pub report_spam_token: Option<Vec<u8>>,
}

fn default_true() -> bool {
    true
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct EnvelopeEntityList {
    pub messages: Vec<EnvelopeEntity>,
}
