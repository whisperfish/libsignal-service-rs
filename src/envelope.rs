pub use crate::proto::Envelope;
use libsignal_core::Pni;
use libsignal_protocol::ServiceId;

impl Envelope {
    pub fn is_unidentified_sender(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::UnidentifiedSender
    }

    pub fn is_prekey_signal_message(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::PrekeyBundle
    }

    pub fn is_receipt(&self) -> bool {
        self.r#type() == crate::proto::envelope::Type::ServerDeliveryReceipt
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

    #[deprecated = "use parse_source_service_id"]
    pub fn source_address(&self) -> ServiceId {
        match self.source_service_id.as_deref() {
            Some(service_id) => {
                ServiceId::parse_from_service_id_string(service_id)
                    .expect("invalid source ProtocolAddress UUID or prefix")
            },
            None => panic!("source_service_id is set"),
        }
    }

    #[deprecated = "use parse_destination_service_id"]
    pub fn destination_address(&self) -> ServiceId {
        match self.destination_service_id.as_deref() {
            Some(service_id) => ServiceId::parse_from_service_id_string(
                service_id,
            )
            .expect("invalid destination ProtocolAddress UUID or prefix"),
            None => panic!("destination_address is set"),
        }
    }

    pub fn parse_destination_service_id(&self) -> Option<ServiceId> {
        crate::utils::parse_service_id_with_fallback(
            self.destination_service_id_binary.as_deref(),
            self.destination_service_id.as_deref(),
        )
    }

    pub fn parse_source_service_id(&self) -> Option<ServiceId> {
        crate::utils::parse_service_id_with_fallback(
            self.source_service_id_binary.as_deref(),
            self.source_service_id.as_deref(),
        )
    }

    pub fn parse_server_guid(&self) -> Option<uuid::Uuid> {
        crate::utils::parse_uuid_with_fallback(
            self.server_guid_binary.as_deref(),
            self.server_guid.as_deref(),
        )
    }

    pub fn parse_updated_pni(&self) -> Option<Pni> {
        crate::utils::parse_pni_with_fallback(
            self.updated_pni_binary.as_deref(),
            self.updated_pni.as_deref(),
            // XXX: this might have to be `false`, but can't find a ref (and it's for the string
            // fallback anyway...
            true,
        )
    }
}

pub(crate) const CIPHER_KEY_SIZE: usize = 32;

pub(crate) const VERSION_OFFSET: usize = 0;
pub(crate) const VERSION_LENGTH: usize = 1;
pub(crate) const IV_OFFSET: usize = VERSION_OFFSET + VERSION_LENGTH;
pub(crate) const IV_LENGTH: usize = 16;
