#![allow(clippy::all)]

use libsignal_core::ServiceId;
use rand::{CryptoRng, Rng};
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

    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalKeyEncrypted(WebSocketMessage)`.
    ///
    /// Signal server no longer encrypts websocket envelope bodies with the
    /// signaling key and no longer sends the `X-Signal-Key` header
    /// (removed in signalapp/Signal-Server@6d87b24). All official clients
    /// (Android, Desktop) now decode envelopes as raw protobuf.
    pub fn is_signal_key_encrypted(&self) -> bool {
        for header in &self.headers {
            let parts: Vec<_> = header.split(':').collect();
            if parts.len() != 2 {
                tracing::warn!(
                    "Got a weird header: {:?}, split in {:?}",
                    header,
                    parts
                );
            }
        }

        false
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
        if let Some(bytes) = self.destination_service_id_binary.as_deref() {
            ServiceId::parse_from_service_id_binary(bytes)
        } else if let Some(s) = self.destination_service_id.as_deref() {
            ServiceId::parse_from_service_id_string(s)
        } else {
            None
        }
    }
}
