include!(concat!(env!("OUT_DIR"), "/signalservice.rs"));

use std::ops::Deref;

impl WebSocketRequestMessage {
    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalServiceEnvelope(WebSocketMessage)`.
    pub fn is_signal_service_envelope(&self) -> bool {
        self.verb.as_ref().map(Deref::deref) == Some("PUT")
            && self.path.as_ref().map(Deref::deref) == Some("/api/v1/message")
    }

    /// Equivalent of
    /// `SignalServiceMessagePipe::isSignalKeyEncrypted(WebSocketMessage)`.
    pub fn is_signal_key_encrypted(&self) -> bool {
        if self.headers.len() == 0 {
            return true;
        }

        for header in &self.headers {
            let parts: Vec<_> = header.split(':').collect();
            if parts.len() != 2 {
                log::warn!(
                    "Got a weird header: {:?}, split in {:?}",
                    header,
                    parts
                );
                continue;
            }

            if parts[0].trim().eq_ignore_ascii_case("X-Signal-Key") {
                if parts[1].trim().eq_ignore_ascii_case("false") {
                    return false;
                }
            }
        }

        false
    }
}
