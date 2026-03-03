#![allow(clippy::all)]

use libsignal_core::{Aci, ServiceId};
use rand::{CryptoRng, Rng};
use reqwest::StatusCode;
include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));
include!(concat!(env!("OUT_DIR"), "/signal.rs"));

impl WebSocketRequestMessage {
    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalServiceEnvelope(WebSocketMessage)`.
    pub fn is_signal_service_envelope(&self) -> bool {
        self.verb.as_deref() == Some("PUT")
            && self.path.as_deref() == Some("/api/v1/message")
    }

    pub fn is_queue_empty(&self) -> bool {
        self.verb.as_deref() == Some("PUT")
            && self.path.as_deref() == Some("/api/v1/queue/empty")
    }
}

impl WebSocketResponseMessage {
    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalServiceEnvelope(WebSocketMessage)`.
    pub fn from_request(msg: &WebSocketRequestMessage) -> Self {
        if msg.is_signal_service_envelope() || msg.is_queue_empty() {
            WebSocketResponseMessage {
                id: msg.id,
                status: Some(200),
                message: Some("OK".to_string()),
                ..Default::default()
            }
        } else {
            WebSocketResponseMessage {
                id: msg.id,
                status: Some(400),
                message: Some("Unknown".to_string()),
                ..Default::default()
            }
        }
    }

    pub fn status_code(&self) -> Option<reqwest::StatusCode> {
        StatusCode::from_u16(self.status().try_into().ok()?).ok()
    }
}

impl SyncMessage {
    pub fn with_padding<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let random_size = csprng.random_range(1..=512);
        let mut padding: Vec<u8> = vec![0; random_size];
        csprng.fill_bytes(&mut padding);

        Self {
            padding: Some(padding),
            ..Default::default()
        }
    }
}

impl sync_message::Sent {
    pub fn parse_destination_service_id(&self) -> Option<ServiceId> {
        crate::utils::parse_service_id_with_fallback(
            self.destination_service_id_binary.as_deref(),
            self.destination_service_id.as_deref(),
        )
    }
}

impl data_message::Reaction {
    pub fn parse_target_author_aci(&self) -> Option<Aci> {
        if let Some(bytes) = self.target_author_aci_binary.as_deref() {
            Some(Aci::from_uuid_bytes(
                bytes
                    .try_into()
                    .inspect_err(|_e| tracing::warn!("binary ACI not 16 bytes"))
                    .ok()?,
            ))
        } else if let Some(s) = self.target_author_aci.as_deref() {
            // Option::inspect_none would be nice
            match Aci::parse_from_service_id_string(s) {
                Some(aci) => Some(aci),
                None => {
                    tracing::warn!("unparsable ACI");
                    None
                },
            }
        } else {
            None
        }
    }
}
