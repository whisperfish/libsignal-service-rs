use std::{convert::TryFrom, time::SystemTime};

use aes::cipher::block_padding::{Iso7816, RawPadding};
use libsignal_protocol::{
    group_decrypt, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
    CiphertextMessageType, DeviceId, IdentityKeyStore, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, ProtocolStore,
    PublicKey, SealedSenderDecryptionResult, SenderCertificate,
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
pub struct ServiceCipher<S, R> {
    protocol_store: S,
    csprng: R,
    trust_root: PublicKey,
    local_uuid: Uuid,
    local_device_id: u32,
}

impl<S, R> ServiceCipher<S, R>
where
    S: ProtocolStore + KyberPreKeyStore + SenderKeyStore + Clone,
    R: Rng + CryptoRng + Clone,
{
    pub fn new(
        protocol_store: S,
        csprng: R,
        trust_root: PublicKey,
        local_uuid: Uuid,
        local_device_id: u32,
    ) -> Self {
        Self {
            protocol_store,
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
                    &mut self.protocol_store,
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

        let server_guid =
            envelope.server_guid.as_ref().and_then(|g| match g.parse() {
                Ok(uuid) => Some(uuid),
                Err(e) => {
                    log::error!("Unparseable server_guid ({})", e);
                    None
                },
            });

        use crate::proto::envelope::Type;
        let plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
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
                    server_guid,
                };

                let mut data = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&ciphertext[..]).unwrap(),
                    &sender,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.csprng,
                )
                .await?
                .as_slice()
                .to_vec();

                let session_record = self
                    .protocol_store
                    .load_session(&sender)
                    .await?
                    .ok_or(SignalProtocolError::SessionNotFound(sender))?;

                strip_padding_version(
                    session_record.session_version()?,
                    &mut data,
                )?;
                Plaintext { metadata, data }
            },
            Type::PlaintextContent => {
                log::warn!("Envelope with plaintext content.  This usually indicates a decryption retry.");
                let metadata = Metadata {
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device(),
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    server_guid,
                };
                Plaintext {
                    metadata,
                    data: ciphertext.clone(),
                }
            },
            Type::Ciphertext => {
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
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
                    server_guid,
                };

                let mut data = message_decrypt_signal(
                    &SignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.csprng,
                )
                .await?
                .as_slice()
                .to_vec();

                let session_record = self
                    .protocol_store
                    .load_session(&sender)
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
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store,
                )
                .await?;

                let sender = ServiceAddress {
                    uuid: Uuid::parse_str(&sender_uuid).map_err(|_| {
                        SignalProtocolError::InvalidSealedSenderMessage(
                            "invalid sender UUID".to_string(),
                        )
                    })?,
                };

                let needs_receipt = if envelope.source_service_id.is_some() {
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
                    server_guid,
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
            .protocol_store
            .load_session(address)
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
                &mut self.protocol_store.clone(),
                &mut self.protocol_store,
                SystemTime::now(),
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
                &mut self.protocol_store.clone(),
                &mut self.protocol_store.clone(),
                SystemTime::now(),
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
        Iso7816::raw_pad(&mut buffer, message_length);
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
    let new_length = Iso7816::raw_unpad(contents)
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
    if session_store.load_session(&address).await?.is_some() {
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
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<SealedSenderDecryptionResult, SignalProtocolError> {
    let usmc =
        sealed_sender_decrypt_to_usmc(ciphertext, identity_store).await?;

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
                kyber_pre_key_store,
                &mut rng,
            )
            .await?
        },
        CiphertextMessageType::SenderKey => {
            group_decrypt(usmc.contents()?, sender_key_store, &remote_address)
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
