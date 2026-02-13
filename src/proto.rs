#![allow(clippy::all)]

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

    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalKeyEncrypted(WebSocketMessage)`.
    pub fn is_signal_key_encrypted(&self) -> bool {
        if self.headers.is_empty() {
            return true;
        }

        for header in &self.headers {
            let parts: Vec<_> = header.split(':').collect();
            if parts.len() != 2 {
                tracing::warn!(
                    "Got a weird header: {:?}, split in {:?}",
                    header,
                    parts
                );
                continue;
            }

            if parts[0].trim().eq_ignore_ascii_case("X-Signal-Key")
                && parts[1].trim().eq_ignore_ascii_case("false")
            {
                return false;
            }
        }

        true
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

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_poll_create_serialization() {
        // Create a poll
        let poll = data_message::PollCreate {
            question: Some("What should we prioritize?".to_string()),
            allow_multiple: Some(false),
            options: vec![
                "Security audit".to_string(),
                "New features".to_string(),
                "Documentation".to_string(),
            ],
        };

        // Verify fields
        assert_eq!(
            poll.question.as_deref(),
            Some("What should we prioritize?")
        );
        assert_eq!(poll.allow_multiple, Some(false));
        assert_eq!(poll.options.len(), 3);

        // Test serialization roundtrip
        let mut buf = Vec::new();
        poll.encode(&mut buf).unwrap();
        let decoded = data_message::PollCreate::decode(&buf[..]).unwrap();

        assert_eq!(poll, decoded);
    }

    #[test]
    fn test_poll_vote_serialization() {
        // Create a vote
        let vote = data_message::PollVote {
            target_author_aci_binary: Some(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]),
            target_sent_timestamp: Some(1706500000000),
            option_indexes: vec![0, 2], // Vote for options 0 and 2
            vote_count: Some(1),
        };

        // Test serialization roundtrip
        let mut buf = Vec::new();
        vote.encode(&mut buf).unwrap();
        let decoded = data_message::PollVote::decode(&buf[..]).unwrap();

        assert_eq!(vote, decoded);
        assert_eq!(decoded.option_indexes, vec![0, 2]);
    }

    #[test]
    fn test_poll_terminate_serialization() {
        let terminate = data_message::PollTerminate {
            target_sent_timestamp: Some(1706500000000),
        };

        let mut buf = Vec::new();
        terminate.encode(&mut buf).unwrap();
        let decoded = data_message::PollTerminate::decode(&buf[..]).unwrap();

        assert_eq!(terminate, decoded);
    }

    #[test]
    fn test_data_message_with_poll() {
        // Create a DataMessage containing a poll
        let poll = data_message::PollCreate {
            question: Some("Approve federation with Group B?".to_string()),
            allow_multiple: Some(false),
            options: vec!["Yes".to_string(), "No".to_string()],
        };

        let data_message = DataMessage {
            poll_create: Some(poll.clone()),
            timestamp: Some(1706500000000),
            ..Default::default()
        };

        // Verify the poll is embedded
        assert!(data_message.poll_create.is_some());
        assert_eq!(
            data_message
                .poll_create
                .as_ref()
                .unwrap()
                .question
                .as_deref(),
            Some("Approve federation with Group B?")
        );

        // Test full message serialization
        let mut buf = Vec::new();
        data_message.encode(&mut buf).unwrap();
        let decoded = DataMessage::decode(&buf[..]).unwrap();

        assert_eq!(decoded.poll_create, Some(poll));
    }

    #[test]
    fn test_protocol_version_includes_polls() {
        // Verify protocol version 8 (POLLS) exists
        // Note: CURRENT = 8 is aliased to Polls in prost output
        assert_eq!(data_message::ProtocolVersion::Polls as i32, 8);

        // Verify Polls is higher than Payments (previous version)
        assert!(
            data_message::ProtocolVersion::Polls as i32
                > data_message::ProtocolVersion::Payments as i32
        );
    }
}
