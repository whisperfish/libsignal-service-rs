use crate::{
    content::{Content, Metadata},
    envelope::Envelope,
    push_service::ServiceError,
    sender::OutgoingPushMessage,
    ServiceAddress,
};

use libsignal_protocol::{
    messages::CiphertextType,
    messages::{PreKeySignalMessage, SignalMessage},
    Address as ProtocolAddress, Context, Deserializable, Serializable,
    SessionCipher, StoreContext,
};

use block_modes::block_padding::{Iso7816, Padding};
use prost::Message;

/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
#[derive(Clone, Debug)]
pub struct ServiceCipher {
    pub(crate) store_context: StoreContext,
    pub(crate) local_address: ServiceAddress,
    pub(crate) context: Context,
}

impl ServiceCipher {
    pub fn from_context(
        context: Context,
        local_address: ServiceAddress,
        store_context: StoreContext,
    ) -> Self {
        Self {
            context,
            store_context,
            local_address,
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
                        envelope.source_address(),
                        envelope.source_device(),
                    )?,
                    Metadata {
                        sender: envelope.source_address(),
                        sender_device: envelope.source_device(),
                        timestamp: envelope.timestamp(),
                        needs_receipt: false,
                    },
                )
            }
            Type::UnidentifiedSender => {
                // is unidentified sender
                return Err(ServiceError::InvalidFrameError {
                    reason: "UnidentifiedSender requires SealedSessionCipher, see: https://github.com/Michael-F-Bryan/libsignal-service-rs/issues/10".into(),
                });
            }
            _ => {
                // else
                return Err(ServiceError::InvalidFrameError {
                    reason: "Envelope has unknown type.".into(),
                });
            }
        };

        let mut plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let cipher = SessionCipher::new(
                    &self.context,
                    &self.store_context,
                    &address,
                )?;
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
            }
            Type::Ciphertext => {
                let cipher = SessionCipher::new(
                    &self.context,
                    &self.store_context,
                    &address,
                )?;
                let buf = cipher.decrypt_message(
                    &SignalMessage::deserialize(&self.context, ciphertext)?,
                )?;
                Plaintext {
                    metadata,
                    data: Vec::from(buf.as_slice()),
                }
            }
            Type::UnidentifiedSender => {
                unimplemented!("UnidentifiedSender requires SealedSessionCipher, please report a bug against libsignal-service-rs.");
            }
            _ => {
                unreachable!("conditions checked in previous match");
            }
        };

        let version =
            self.store_context.load_session(&address)?.state().version();

        strip_padding(version, &mut plaintext.data)?;
        Ok(plaintext)
    }

    /// Equivalent of `SignalServiceCipher::getPreferredProtocolAddress`
    fn get_preferred_protocol_address(
        &self,
        address: ServiceAddress,
        device: u32,
    ) -> Result<ProtocolAddress, ServiceError> {
        if let Some(ref uuid) = address.uuid {
            let address = ProtocolAddress::new(uuid, device as i32);
            if self.store_context.contains_session(&address)? {
                return Ok(address);
            }
        } else if let Some(ref e164) = address.e164 {
            let address = ProtocolAddress::new(e164, device as i32);
            if self.store_context.contains_session(&address)? {
                return Ok(address);
            }
        }

        Ok(ProtocolAddress::new(address.identifier(), device as i32))
    }

    pub fn encrypt(
        &self,
        address: &ProtocolAddress,
        unindentified_access: Option<bool>,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, ServiceError> {
        if unindentified_access.is_some() {
            unimplemented!("unidentified access is not implemented");
        } else {
            let session_cipher = SessionCipher::new(
                &self.context,
                &self.store_context,
                address,
            )?;

            let padded_content =
                add_padding(session_cipher.get_session_version()?, content)?;
            let message = session_cipher.encrypt(&padded_content)?;

            let destination_registration_id =
                session_cipher.get_remote_registration_id()?;
            let body = base64::encode(message.serialize()?);
            use crate::proto::envelope::Type;
            let message_type = match message.get_type()? {
                CiphertextType::PreKey => Type::PrekeyBundle,
                CiphertextType::Signal => Type::Ciphertext,
                t => panic!("Bad type: {:?}", t),
            } as u32;
            Ok(OutgoingPushMessage {
                r#type: message_type,
                destination_device_id: address.device_id(),
                destination_registration_id,
                content: body,
            })
        }
    }
}

struct Plaintext {
    metadata: Metadata,
    data: Vec<u8>,
}

fn add_padding(version: u32, contents: &[u8]) -> Result<Vec<u8>, ServiceError> {
    if version < 2 {
        Err(ServiceError::InvalidFrameError {
            reason: format!("Unknown version {}", version),
        })
    } else if version == 2 {
        Ok(contents.to_vec())
    } else {
        let message_length = contents.len();
        let message_length_with_terminator = contents.len() + 1;
        let mut message_part_count = message_length_with_terminator / 160;
        if message_length_with_terminator % 160 != 0 {
            message_part_count += 1;
        }

        let message_length_with_padding = message_part_count * 160;

        let mut buffer = vec![0u8; message_length_with_padding];
        buffer[..message_length].copy_from_slice(contents);
        Iso7816::pad_block(&mut buffer, message_length).map_err(|e| {
            ServiceError::InvalidFrameError {
                reason: format!("Invalid message padding: {:?}", e),
            }
        })?;
        Ok(buffer)
    }
}

fn strip_padding(
    version: u32,
    contents: &mut Vec<u8>,
) -> Result<(), ServiceError> {
    if version < 2 {
        Err(ServiceError::InvalidFrameError {
            reason: format!("Unknown version {}", version),
        })
    } else if version == 2 {
        Ok(())
    } else {
        let new_length = Iso7816::unpad(contents)
            .map_err(|e| ServiceError::InvalidFrameError {
                reason: format!("Invalid message padding: {:?}", e),
            })?
            .len();
        contents.resize(new_length, 0);
        Ok(())
    }
}
