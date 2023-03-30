use std::convert::TryFrom;

use block_modes::block_padding::{Iso7816, Padding};
use libsignal_protocol::{
    group_decrypt, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
    CiphertextMessageType, Context, DeviceId, IdentityKeyStore,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, PublicKey,
    SealedSenderDecryptionResult, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyStore, SessionStore, SignalMessage,
    SignalProtocolError, SignedPreKeyStore,
};
use prost::Message;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

use crate::{
    content::{Content, Metadata},
    envelope::Envelope,
    push_service::ServiceError,
    sender::OutgoingPushMessage,
    ServiceAddress,
};
/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
#[derive(Clone)]
pub struct ServiceCipher<S, I, SP, P, SK, R> {
    session_store: S,
    identity_key_store: I,
    signed_pre_key_store: SP,
    pre_key_store: P,
    sender_key_store: SK,
    csprng: R,
    trust_root: PublicKey,
    local_uuid: Uuid,
    local_device_id: u32,
}

impl<S, I, SP, P, SK, R> ServiceCipher<S, I, SP, P, SK, R>
where
    S: SessionStore + Clone,
    I: IdentityKeyStore + Clone,
    SP: SignedPreKeyStore + Clone,
    SK: SenderKeyStore + Clone,
    P: PreKeyStore + Clone,
    R: Rng + CryptoRng + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_store: S,
        identity_key_store: I,
        signed_pre_key_store: SP,
        pre_key_store: P,
        sender_key_store: SK,
        csprng: R,
        trust_root: PublicKey,
        local_uuid: Uuid,
        local_device_id: u32,
    ) -> Self {
        Self {
            session_store,
            identity_key_store,
            signed_pre_key_store,
            pre_key_store,
            sender_key_store,
            csprng,
            trust_root,
            local_uuid,
            local_device_id,
        }
    }

    /// Opens ("decrypts") an envelope.
    ///
    /// Envelopes may be empty, in which case this method returns `Ok(None)`
    pub async fn open_envelope(
        &mut self,
        envelope: Envelope,
    ) -> Result<Option<Content>, ServiceError> {
        if envelope.content.is_some() {
            let plaintext = self.decrypt(&envelope).await?;
            let message =
                crate::proto::Content::decode(plaintext.data.as_slice())?;
            if let Some(bytes) = message.sender_key_distribution_message {
                let skdm = SenderKeyDistributionMessage::try_from(&bytes[..])?;
                process_sender_key_distribution_message(
                    &plaintext.metadata.protocol_address(),
                    &skdm,
                    &mut self.sender_key_store,
                    None,
                )
                .await?;
                Ok(None)
            } else {
                let content = Content::from_proto(message, plaintext.metadata)?;
                Ok(Some(content))
            }
        } else {
            Ok(None)
        }
    }

    /// Equivalent of decrypt(Envelope, ciphertext)
    ///
    /// Triage of legacy messages happens inside this method, as opposed to the
    /// Java implementation, because it makes the borrow checker and the
    /// author happier.
    async fn decrypt(
        &mut self,
        envelope: &Envelope,
    ) -> Result<Plaintext, ServiceError> {
        let ciphertext = if let Some(msg) = envelope.content.as_ref() {
            msg
        } else {
            return Err(ServiceError::InvalidFrameError {
                reason:
                    "Envelope should have either a legacy message or content."
                        .into(),
            });
        };

        use crate::proto::envelope::Type;
        let plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let sender = get_preferred_protocol_address(
                    &self.session_store,
                    &envelope.source_address(),
                    envelope.source_device().into(),
                )
                .await?;
                let metadata = Metadata {
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device(),
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                };

                let mut data = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&ciphertext[..]).unwrap(),
                    &sender,
                    &mut self.session_store,
                    &mut self.identity_key_store,
                    &mut self.pre_key_store,
                    &mut self.signed_pre_key_store,
                    &mut self.csprng,
                    None,
                )
                .await?
                .as_slice()
                .to_vec();

                let session_record = self
                    .session_store
                    .load_session(&sender, None)
                    .await?
                    .ok_or(SignalProtocolError::SessionNotFound(sender))?;

                strip_padding_version(
                    session_record.session_version()?,
                    &mut data,
                )?;
                Plaintext { metadata, data }
            },
            Type::Ciphertext => {
                let sender = get_preferred_protocol_address(
                    &self.session_store,
                    &envelope.source_address(),
                    envelope.source_device().into(),
                )
                .await?;
                let metadata = Metadata {
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device(),
                    timestamp: envelope.timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                };

                let mut data = message_decrypt_signal(
                    &SignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &mut self.session_store,
                    &mut self.identity_key_store,
                    &mut self.csprng,
                    None,
                )
                .await?
                .as_slice()
                .to_vec();

                let session_record = self
                    .session_store
                    .load_session(&sender, None)
                    .await?
                    .ok_or(SignalProtocolError::SessionNotFound(sender))?;

                strip_padding_version(
                    session_record.session_version()?,
                    &mut data,
                )?;
                Plaintext { metadata, data }
            },
            Type::UnidentifiedSender => {
                let SealedSenderDecryptionResult {
                    sender_uuid,
                    sender_e164: _,
                    device_id,
                    mut message,
                } = sealed_sender_decrypt(
                    ciphertext,
                    &self.trust_root,
                    envelope.timestamp(),
                    None,
                    self.local_uuid.to_string(),
                    self.local_device_id.into(),
                    &mut self.identity_key_store,
                    &mut self.session_store,
                    &mut self.pre_key_store,
                    &mut self.signed_pre_key_store,
                    &mut self.sender_key_store,
                    None,
                )
                .await?;

                let sender = ServiceAddress {
                    uuid: Uuid::parse_str(&sender_uuid).map_err(|_| {
                        SignalProtocolError::InvalidSealedSenderMessage(
                            "invalid sender UUID".to_string(),
                        )
                    })?,
                };

                let needs_receipt = if envelope.source_uuid.is_some() {
                    log::warn!("Received an unidentified delivery over an identified channel.  Marking needs_receipt=false");
                    false
                } else {
                    true
                };

                let metadata = Metadata {
                    sender,
                    sender_device: device_id.into(),
                    timestamp: envelope.timestamp(),
                    unidentified_sender: true,
                    needs_receipt,
                };

                strip_padding(&mut message)?;

                Plaintext {
                    metadata,
                    data: message,
                }
            },
            _ => {
                // else
                return Err(ServiceError::InvalidFrameError {
                    reason: format!(
                        "Envelope has unknown type {:?}.",
                        envelope.r#type()
                    ),
                });
            },
        };
        Ok(plaintext)
    }

    pub(crate) async fn encrypt(
        &mut self,
        address: &ProtocolAddress,
        unindentified_access: Option<&SenderCertificate>,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, ServiceError> {
        let session_record = self
            .session_store
            .load_session(address, None)
            .await?
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(address.clone())
            })?;

        let padded_content =
            add_padding(session_record.session_version()?, content)?;

        if let Some(unindentified_access) = unindentified_access {
            let destination_registration_id =
                session_record.remote_registration_id()?;

            let message = sealed_sender_encrypt(
                address,
                unindentified_access,
                &padded_content,
                &mut self.session_store,
                &mut self.identity_key_store,
                None,
                &mut self.csprng,
            )
            .await?;

            use crate::proto::envelope::Type;
            Ok(OutgoingPushMessage {
                r#type: Type::UnidentifiedSender as u32,
                destination_device_id: address.device_id().into(),
                destination_registration_id,
                content: base64::encode(message),
            })
        } else {
            let message = message_encrypt(
                &padded_content,
                address,
                &mut self.session_store,
                &mut self.identity_key_store,
                None,
            )
            .await?;

            let destination_registration_id =
                session_record.remote_registration_id()?;

            let body = base64::encode(message.serialize());

            use crate::proto::envelope::Type;
            let message_type = match message.message_type() {
                CiphertextMessageType::PreKey => Type::PrekeyBundle,
                CiphertextMessageType::Whisper => Type::Ciphertext,
                t => panic!("Bad type: {:?}", t),
            } as u32;
            Ok(OutgoingPushMessage {
                r#type: message_type,
                destination_device_id: address.device_id().into(),
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

#[allow(clippy::comparison_chain)]
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

#[allow(clippy::comparison_chain)]
fn strip_padding_version(
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
        strip_padding(contents)?;
        Ok(())
    }
}

#[allow(clippy::comparison_chain)]
fn strip_padding(contents: &mut Vec<u8>) -> Result<(), ServiceError> {
    let new_length = Iso7816::unpad(contents)
        .map_err(|e| ServiceError::InvalidFrameError {
            reason: format!("Invalid message padding: {:?}", e),
        })?
        .len();
    contents.resize(new_length, 0);
    Ok(())
}

/// Equivalent of `SignalServiceCipher::getPreferredProtocolAddress`
pub async fn get_preferred_protocol_address<S: SessionStore>(
    session_store: &S,
    address: &ServiceAddress,
    device_id: DeviceId,
) -> Result<ProtocolAddress, libsignal_protocol::error::SignalProtocolError> {
    let address = address.to_protocol_address(device_id);
    if session_store.load_session(&address, None).await?.is_some() {
        return Ok(address);
    }

    Ok(address)
}

/// Decrypt a Sealed Sender message `ciphertext` in either the v1 or v2 format, validate its sender
/// certificate, and then decrypt the inner message payload.
///
/// This method calls [`sealed_sender_decrypt_to_usmc`] to extract the sender information, including
/// the embedded [`SenderCertificate`]. The sender certificate (signed by the [`ServerCertificate`])
/// is then validated against the `trust_root` baked into the client to ensure that the sender's
/// identity was not forged.
#[allow(clippy::too_many_arguments)]
async fn sealed_sender_decrypt(
    ciphertext: &[u8],
    trust_root: &PublicKey,
    timestamp: u64,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: DeviceId,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    ctx: Context,
) -> Result<SealedSenderDecryptionResult, SignalProtocolError> {
    let usmc =
        sealed_sender_decrypt_to_usmc(ciphertext, identity_store, ctx).await?;

    if !usmc.sender()?.validate(trust_root, timestamp)? {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "trust root validation failed".to_string(),
        ));
    }

    let is_local_uuid = local_uuid == usmc.sender()?.sender_uuid()?;

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid)
        && usmc.sender()?.sender_device_id()? == local_device_id
    {
        return Err(SignalProtocolError::SealedSenderSelfSend);
    }

    let mut rng = rand::rngs::OsRng;

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );

    let message = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            message_decrypt_signal(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                &mut rng,
                ctx,
            )
            .await?
        },
        CiphertextMessageType::PreKey => {
            let ctext = PreKeySignalMessage::try_from(usmc.contents()?)?;
            message_decrypt_prekey(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                &mut rng,
                ctx,
            )
            .await?
        },
        CiphertextMessageType::SenderKey => {
            group_decrypt(
                usmc.contents()?,
                sender_key_store,
                &remote_address,
                ctx,
            )
            .await?
        },
        msg_type => {
            return Err(SignalProtocolError::InvalidMessage(
                msg_type,
                "unexpected message type for sealed_sender_decrypt",
            ));
        },
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}
