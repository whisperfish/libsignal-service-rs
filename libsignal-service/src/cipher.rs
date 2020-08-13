use crate::{
    content::{Content, Metadata},
    envelope::Envelope,
    push_service::ServiceError,
    ServiceAddress,
};

use libsignal_protocol::{
    messages::{PreKeySignalMessage, SignalMessage},
    Address as ProtocolAddress, Context, Deserializable, SessionCipher,
    StoreContext,
};
use prost::Message;

/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
pub struct ServiceCipher {
    store: StoreContext,
    local: ServiceAddress,
    context: Context,
}

impl ServiceCipher {
    pub fn from_context(
        context: Context,
        local: ServiceAddress,
        store: StoreContext,
    ) -> Self {
        Self {
            context,
            store,
            local,
        }
    }

    /// Opens ("decrypts") an envelope.
    ///
    /// Envelopes may be empty, in which case this method returns `Ok(None)`
    pub fn open_envelope(
        &mut self,
        envelope: Envelope,
    ) -> Result<Option<Content>, ServiceError> {
        if envelope.legacy_message.is_some() {
            let plaintext = self.decrypt(&envelope)?;
            let message =
                crate::proto::DataMessage::decode(plaintext.data.as_slice())?;
            Ok(Some(Content::from_body(message, plaintext.metadata)))
        } else if envelope.content.is_some() {
            let plaintext = self.decrypt(&envelope)?;
            let message =
                crate::proto::Content::decode(plaintext.data.as_slice())?;
            Ok(Content::from_proto(message, plaintext.metadata))
        } else {
            Ok(None)
        }
    }

    /// Equivalent of decrypt(Envelope, ciphertext)
    ///
    /// Triage of legacy messages happens inside this method, as opposed to the
    /// Java implementation, because it makes the borrow checker and the
    /// author happier.
    fn decrypt(
        &mut self,
        envelope: &Envelope,
    ) -> Result<Plaintext, ServiceError> {
        let ciphertext = if let Some(msg) = envelope.legacy_message.as_ref() {
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

        use crate::proto::envelope::Type;
        let (address, metadata) = match envelope.r#type() {
            Type::PrekeyBundle | Type::Ciphertext => {
                // is prekey signal message || is signal message
                (
                    self.get_preferred_protocol_address(
                        envelope
                            .source_address()
                            .expect("Envelope with source"),
                        envelope.source_device(),
                    )?,
                    Metadata {
                        sender: envelope
                            .source_address()
                            .expect("envelope with source"),
                        sender_device: envelope.source_device(),
                        timestamp: envelope.timestamp(),
                        needs_receipt: false,
                    },
                )
            },
            Type::UnidentifiedSender => {
                // is unidentified sender
                unimplemented!("UnidentifiedSender requires SealedSessionCipher, please report a bug against libsignal-service-rs.");
            },
            _ => {
                // else
                return Err(ServiceError::InvalidFrameError {
                    reason: "Envelope has unknown type.".into(),
                });
            },
        };

        let mut plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let cipher =
                    SessionCipher::new(&self.context, &self.store, &address)?;
                let buf = cipher.decrypt_pre_key_message(
                    &PreKeySignalMessage::deserialize(
                        &self.context,
                        ciphertext,
                    )?,
                )?;
                Plaintext {
                    metadata,
                    data: Vec::from(buf.as_slice()),
                }
            },
            Type::Ciphertext => {
                let cipher =
                    SessionCipher::new(&self.context, &self.store, &address)?;
                let buf = cipher.decrypt_message(
                    &SignalMessage::deserialize(&self.context, ciphertext)?,
                )?;
                Plaintext {
                    metadata,
                    data: Vec::from(buf.as_slice()),
                }
            },
            Type::UnidentifiedSender => {
                unimplemented!("UnidentifiedSender requires SealedSessionCipher, please report a bug against libsignal-service-rs.");
            },
            _ => {
                unreachable!("conditions checked in previous match");
            },
        };

        let version = self.store.load_session(&address)?.state().version();

        strip_padding(version, &mut plaintext.data)?;
        Ok(plaintext)
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

fn strip_padding(
    version: u32,
    contents: &mut Vec<u8>,
) -> Result<(), ServiceError> {
    if version < 2 {
        return Err(ServiceError::InvalidFrameError {
            reason: format!("Unknown version {}", version),
        });
    } else if version == 2 {
        // No-op
        return Ok(());
    }

    let first_non_null = contents.iter().rposition(|b| *b != 0x00);
    if let Some(start) = first_non_null {
        if contents[start] != 0x80 {
            log::warn!("Badly padded message. Proceeding");
            return Ok(());
        } else {
            contents.truncate(start);
        }
    }
    Ok(())
}
