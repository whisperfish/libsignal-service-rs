use crate::{
    content::{Content, ContentBody, Metadata},
    envelope::Envelope,
    push_service::ServiceError,
    ServiceAddress,
};

use libsignal_protocol::{Address as ProtocolAddress, StoreContext};
use prost::Message;

/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
pub struct ServiceCipher {
    store: StoreContext,
    local: ServiceAddress,
}

impl ServiceCipher {
    pub fn from_context(local: ServiceAddress, store: StoreContext) -> Self {
        Self { store, local }
    }

    pub fn open_envelope(
        &mut self,
        envelope: Envelope,
    ) -> Result<Content, ServiceError> {
        let plaintext = self.decrypt(&envelope)?;
        if envelope.legacy_message.is_some() {
            let message =
                crate::proto::DataMessage::decode(&plaintext.data as &[u8])?;
            let body = crate::models::Message {
                attachments: vec![], // XXX
                flags: message.flags(),
                // group: message.group.unwrap(), // XXX
                group: None,
                message: message.body().to_string(),
                source: plaintext.metadata.sender.e164.clone(),
                timestamp: message.timestamp(),
            };
            Ok(Content::from_body(body, plaintext.metadata))
        } else {
            let message =
                crate::proto::Content::decode(&plaintext.data as &[u8])?;
            unimplemented!()
        }
    }

    fn decrypt(
        &mut self,
        envelope: &Envelope,
    ) -> Result<Plaintext, ServiceError> {
        let _ciphertext = if let Some(msg) = envelope.legacy_message.as_ref() {
            msg
        } else if let Some(msg) = envelope.content.as_ref() {
            msg
        } else {
            return Err(ServiceError::InvalidFrameError {
                reason:
                    "Envelope should have either a legacy message or content."
                        .into(),
            });
        };
        unimplemented!()
    }

    /// Equivalent of `SignalServiceCipher::getPreferredProtocolAddress`
    fn get_preferred_protocol_address(
        &self,
        address: ServiceAddress,
        device: u32,
    ) -> Result<ProtocolAddress, ServiceError> {
        let uuid = address
            .uuid
            .as_deref()
            .map(|uuid| ProtocolAddress::new(uuid, device as i32));
        let e164 = ProtocolAddress::new(&address.e164, device as i32);

        if let Some(uuid) = uuid {
            if self.store.contains_session(&uuid)? {
                return Ok(uuid);
            }
        }

        if self.store.contains_session(&e164)? {
            return Ok(e164);
        }

        return Ok(ProtocolAddress::new(
            address.get_identifier(),
            device as i32,
        ));
    }
}

struct Plaintext {
    metadata: Metadata,
    data: Vec<u8>,
}
