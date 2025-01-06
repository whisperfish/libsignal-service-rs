use libsignal_protocol::ServiceId;

pub use crate::proto::Envelope;

impl Envelope {
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

    pub fn source_address(&self) -> ServiceId {
        match self.source_service_id.as_deref() {
            Some(service_id) => {
                ServiceId::parse_from_service_id_string(service_id)
                    .expect("invalid source ProtocolAddress UUID or prefix")
            },
            None => panic!("source_service_id is set"),
        }
    }

    pub fn destination_address(&self) -> ServiceId {
        match self.destination_service_id.as_deref() {
            Some(service_id) => ServiceId::parse_from_service_id_string(
                service_id,
            )
            .expect("invalid destination ProtocolAddress UUID or prefix"),
            None => panic!("destination_address is set"),
        }
    }
}
