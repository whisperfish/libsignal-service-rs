use std::{convert::TryFrom, fmt, time::SystemTime};

use aes::cipher::block_padding::{Iso7816, RawPadding};
use base64::prelude::*;
use libsignal_core::ServiceIdKind;
use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
    message_decrypt_prekey, message_decrypt_signal, message_encrypt,
    process_sender_key_distribution_message, sealed_sender_decrypt_to_usmc,
    sealed_sender_encrypt, sealed_sender_multi_recipient_encrypt,
    CiphertextMessageType, ContentHint, DeviceId, IdentityKeyStore,
    KyberPreKeyStore, PlaintextContent, PreKeySignalMessage, PreKeyStore,
    ProtocolAddress, ProtocolStore, PublicKey, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyStore, ServiceId, SessionRecord,
    SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyStore,
    Timestamp, UnidentifiedSenderMessageContent,
};
use prost::Message;
use rand::{rng, CryptoRng, Rng};
use uuid::Uuid;

use crate::{
    content::{Content, ContentBody, Metadata},
    envelope::Envelope,
    push_service::ServiceError,
    sender::OutgoingPushMessage,
    session_store::SessionStoreExt,
    utils::BASE64_RELAXED,
    ServiceIdExt,
};

/// Decrypts incoming messages and encrypts outgoing messages.
///
/// Equivalent of SignalServiceCipher in Java.
#[derive(Clone)]
pub struct ServiceCipher<S> {
    protocol_store: S,
    trust_roots: Vec<PublicKey>,
    local_uuid: Uuid,
    local_device_id: DeviceId,
}

impl<S> fmt::Debug for ServiceCipher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCipher")
            .field("protocol_store", &"...")
            .field("trust_root", &"...")
            .field("local_uuid", &self.local_uuid)
            .field("local_device_id", &self.local_device_id)
            .finish()
    }
}

fn debug_envelope(envelope: &Envelope) -> String {
    if envelope.content.is_none() {
        "Envelope { empty }".to_string()
    } else {
        format!(
            "Envelope {{ \
                 source_address: {:?}, \
                 source_device: {:?}, \
                 server_guid: {:?}, \
                 timestamp: {:?}, \
                 content: {} bytes, \
             }}",
            envelope.source_service_id,
            envelope.source_device(),
            envelope.server_guid(),
            envelope.timestamp(),
            envelope.content().len(),
        )
    }
}

impl<S> ServiceCipher<S>
where
    S: ProtocolStore + SenderKeyStore + SessionStoreExt + Clone,
{
    pub fn new(
        protocol_store: S,
        trust_roots: Vec<PublicKey>,
        local_uuid: Uuid,
        local_device_id: DeviceId,
    ) -> Self {
        Self {
            protocol_store,
            trust_roots,
            local_uuid,
            local_device_id,
        }
    }

    /// Opens ("decrypts") an envelope.
    ///
    /// Envelopes may be empty, in which case this method returns `Ok(None)`
    #[tracing::instrument(skip(envelope, csprng), fields(envelope = debug_envelope(&envelope)))]
    pub async fn open_envelope<R: Rng + CryptoRng>(
        &mut self,
        envelope: Envelope,
        csprng: &mut R,
    ) -> Result<Option<Content>, ServiceError> {
        if envelope.content.is_some() {
            let plaintext = self.decrypt(&envelope, csprng).await?;
            let was_plaintext = plaintext.metadata.was_plaintext;

            // Debug logging for plaintext messages to understand their structure
            if was_plaintext {
                let data_len = plaintext.data.len();
                let preview_len = std::cmp::min(32, data_len);
                let preview = &plaintext.data[..preview_len];
                tracing::debug!(
                    data_len,
                    preview_hex = %hex::encode(preview),
                    "plaintext message data before Content decode"
                );
            }

            let message =
                crate::proto::Content::decode(plaintext.data.as_slice())?;

            tracing::Span::current()
                .record("envelope_metadata", plaintext.metadata.to_string());

            // Sanity test: if the envelope was plaintext, the message should *only* be a
            // decryption failure error
            if was_plaintext {
                if let crate::proto::Content {
                    data_message: None,
                    sync_message: None,
                    call_message: None,
                    null_message: None,
                    receipt_message: None,
                    typing_message: None,
                    sender_key_distribution_message: None,
                    decryption_error_message: Some(decryption_error_message),
                    story_message: None,
                    pni_signature_message: None,
                    edit_message: None,
                } = &message
                {
                    // Parse the DecryptionErrorMessage to extract structured data
                    let parsed_error =
                        crate::proto::DecryptionErrorMessage::decode(
                            decryption_error_message.as_slice(),
                        );

                    match &parsed_error {
                        Ok(decryption_error) => {
                            tracing::warn!(
                                ?envelope,
                                timestamp = decryption_error.timestamp,
                                device_id = decryption_error.device_id,
                                has_ratchet_key = decryption_error.ratchet_key.is_some(),
                                "Received a decryption error message - recipient could not decrypt message"
                            );
                        },
                        Err(e) => {
                            tracing::warn!(
                                ?envelope,
                                error = %e,
                                raw_data = %hex::encode(decryption_error_message),
                                "Received a decryption error message but failed to parse it"
                            );
                        },
                    }

                    // Pass through the DecryptionErrorMessage to the application layer
                    // for retry handling
                    match parsed_error {
                        Ok(decryption_error) => {
                            let content = Content {
                                metadata: plaintext.metadata,
                                body: ContentBody::DecryptionErrorMessage(
                                    decryption_error,
                                ),
                            };
                            return Ok(Some(content));
                        },
                        Err(e) => {
                            tracing::warn!(
                                ?envelope,
                                error = %e,
                                raw_data = %hex::encode(decryption_error_message),
                                "Failed to parse DecryptionErrorMessage, skipping"
                            );
                            return Ok(None);
                        },
                    }
                } else {
                    tracing::error!(
                        ?envelope,
                        "Received a plaintext envelope with a non-decryption error message."
                    );
                    return Ok(None);
                }
            }

            if message.sync_message.is_some()
                && plaintext.metadata.sender.aci().map(Into::into)
                    != Some(self.local_uuid)
            {
                tracing::warn!("Source is not ourself.");
                return Ok(None);
            }

            if let Some(bytes) = message.sender_key_distribution_message {
                let skdm = SenderKeyDistributionMessage::try_from(&bytes[..])?;
                process_sender_key_distribution_message(
                    &plaintext.metadata.protocol_address()?,
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
    #[tracing::instrument(skip(envelope, csprng), fields(envelope = debug_envelope(envelope)))]
    async fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        envelope: &Envelope,
        csprng: &mut R,
    ) -> Result<Plaintext, ServiceError> {
        let ciphertext = if let Some(msg) = envelope.content.as_ref() {
            msg
        } else {
            return Err(ServiceError::InvalidFrame {
                reason:
                    "envelope should have either a legacy message or content.",
            });
        };

        let server_guid =
            envelope.server_guid.as_ref().and_then(|g| match g.parse() {
                Ok(uuid) => Some(uuid),
                Err(e) => {
                    tracing::error!(
                        ?envelope,
                        "Unparseable server_guid ({})",
                        e
                    );
                    None
                },
            });

        if envelope.destination_service_id.is_none() {
            tracing::warn!(
                "missing destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "missing destination service id",
            });
        }

        if envelope.destination_address().raw_uuid() != self.local_uuid {
            tracing::warn!(
                "mismatching destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "mismatch destination service id",
            });
        }

        if envelope.destination_address().kind() == ServiceIdKind::Pni
            && envelope.source_service_id.is_none()
        {
            tracing::warn!("received sealed sender message to our PNI; ignoring invalid message");
            return Err(ServiceError::InvalidFrame {
                reason: "sealed sender received on our PNI",
            });
        }

        if envelope.source_service_id.is_some()
            && envelope.source_address().kind() == ServiceIdKind::Pni
            && envelope.r#type() != Type::ServerDeliveryReceipt
        {
            tracing::warn!("got a message from a PNI that was not a ServerDeliveryReceipt; ignoring invalid message");
            return Err(ServiceError::InvalidFrame {
                reason: "PNI received a non-ServerDeliveryReceipt",
            });
        }

        use crate::proto::envelope::Type;
        let plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &envelope.source_address(),
                    envelope.source_device().try_into()?,
                )
                .await?;
                let metadata = Metadata {
                    destination: envelope.destination_address(),
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device().try_into()?,
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: false,

                    server_guid,
                };

                let mut data = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&ciphertext[..]).unwrap(),
                    &sender,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    csprng,
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
                tracing::warn!(?envelope, "Envelope with plaintext content.  This usually indicates a decryption retry.");
                let metadata = Metadata {
                    destination: envelope.destination_address(),
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device().try_into()?,
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: true,

                    server_guid,
                };
                // PlaintextContent is a wrapper with a 0xC0 prefix byte and 0x80 padding boundary byte.
                // The body() method returns bytes[1..], which includes the Content protobuf
                // followed by the PADDING_BOUNDARY_BYTE (0x80). We must strip the last byte
                // to get the valid Content protobuf.
                let plaintext_content =
                    PlaintextContent::try_from(ciphertext.as_slice())?;
                let body = plaintext_content.body();
                // Strip the PADDING_BOUNDARY_BYTE (0x80) from the end
                let content_bytes = &body[..body.len().saturating_sub(1)];
                Plaintext {
                    metadata,
                    data: content_bytes.to_vec(),
                }
            },
            Type::Ciphertext => {
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &envelope.source_address(),
                    envelope.source_device().try_into()?,
                )
                .await?;
                let metadata = Metadata {
                    destination: envelope.destination_address(),
                    sender: envelope.source_address(),
                    sender_device: envelope.source_device().try_into()?,
                    timestamp: envelope.timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: false,

                    server_guid,
                };

                let mut data = message_decrypt_signal(
                    &SignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    csprng,
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
                let LocalSealedSenderDecryptionResult {
                    sender_uuid,
                    sender_e164: _,
                    device_id,
                    mut message,
                    was_plaintext,
                } = sealed_sender_decrypt(
                    ciphertext,
                    &self.trust_roots,
                    Timestamp::from_epoch_millis(envelope.timestamp()),
                    None,
                    self.local_uuid.to_string(),
                    self.local_device_id,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store,
                )
                .await?;

                let Some(sender) =
                    ServiceId::parse_from_service_id_string(&sender_uuid)
                else {
                    return Err(
                        SignalProtocolError::InvalidSealedSenderMessage(
                            "invalid sender UUID".to_string(),
                        )
                        .into(),
                    );
                };

                let needs_receipt = if envelope.source_service_id.is_some() {
                    tracing::warn!(?envelope, "Received an unidentified delivery over an identified channel.  Marking needs_receipt=false");
                    false
                } else {
                    true
                };

                if sender.kind() == ServiceIdKind::Pni {
                    tracing::warn!(
                        "sealed sender used for PNI; ignoring invalid message"
                    );
                    return Err(ServiceError::InvalidFrame {
                        reason: "sealed sender used for PNI",
                    });
                }

                let metadata = Metadata {
                    destination: envelope.destination_address(),
                    sender,
                    sender_device: device_id,
                    timestamp: envelope.timestamp(),
                    unidentified_sender: true,
                    needs_receipt,
                    was_plaintext,

                    server_guid,
                };

                // Plaintext messages don't have padding to strip
                if !was_plaintext {
                    strip_padding(&mut message)?;
                }

                Plaintext {
                    metadata,
                    data: message,
                }
            },
            _ => {
                // else
                return Err(ServiceError::InvalidFrame {
                    reason: "envelope has unknown type",
                });
            },
        };
        Ok(plaintext)
    }

    #[tracing::instrument(
        skip(address, unidentified_access, content, csprng),
        fields(
            address = %address,
            with_unidentified_access = unidentified_access.is_some(),
            content_length = content.len(),
        )
    )]
    pub(crate) async fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        address: &ProtocolAddress,
        unidentified_access: Option<&SenderCertificate>,
        content: &[u8],
        csprng: &mut R,
    ) -> Result<OutgoingPushMessage, ServiceError> {
        let mut rng = rng();

        let session_record = self
            .protocol_store
            .load_session(address)
            .await?
            .ok_or_else(|| {
            SignalProtocolError::SessionNotFound(address.clone())
        })?;

        let padded_content =
            add_padding(session_record.session_version()?, content)?;

        if let Some(unindentified_access) = unidentified_access {
            let destination_registration_id =
                session_record.remote_registration_id()?;

            let message = sealed_sender_encrypt(
                address,
                unindentified_access,
                &padded_content,
                &mut self.protocol_store.clone(),
                &mut self.protocol_store,
                SystemTime::now(),
                csprng,
            )
            .await?;

            use crate::proto::envelope::Type;
            Ok(OutgoingPushMessage {
                r#type: Type::UnidentifiedSender as u32,
                destination_device_id: address.device_id(),
                destination_registration_id,
                content: BASE64_RELAXED.encode(message),
            })
        } else {
            let message = message_encrypt(
                &padded_content,
                address,
                &mut self.protocol_store.clone(),
                &mut self.protocol_store.clone(),
                SystemTime::now(),
                &mut rng,
            )
            .await?;

            let destination_registration_id =
                session_record.remote_registration_id()?;

            let body = BASE64_RELAXED.encode(message.serialize());

            use crate::proto::envelope::Type;
            let message_type = match message.message_type() {
                CiphertextMessageType::PreKey => Type::PrekeyBundle,
                CiphertextMessageType::Whisper => Type::Ciphertext,
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

    /// Encrypt a message for multiple recipients using Sealed Sender Multi-Recipient.
    ///
    /// This is used for group messages with Group Send Endorsements. The message is
    /// encrypted once and can be delivered to multiple recipients in a single request.
    ///
    /// # Arguments
    ///
    /// * `recipients` - List of protocol addresses for each recipient
    /// * `sender_certificate` - The sender certificate for anonymous delivery
    /// * `content` - The plaintext content to encrypt
    /// * `excluded_recipients` - Service IDs to exclude (typically just the sender)
    /// * `csprng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// Returns the encrypted multi-recipient payload on success.
    pub async fn encrypt_for_multi_recipient<R: Rng + CryptoRng>(
        &mut self,
        recipients: &[ProtocolAddress],
        sender_certificate: &SenderCertificate,
        content: &[u8],
        excluded_recipients: Vec<ServiceId>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ServiceError> {
        // Load all sessions for recipients
        let mut sessions: Vec<SessionRecord> =
            Vec::with_capacity(recipients.len());
        for address in recipients {
            let session = self
                .protocol_store
                .load_session(address)
                .await?
                .ok_or_else(|| {
                    SignalProtocolError::SessionNotFound(address.clone())
                })?;
            sessions.push(session);
        }

        // For multi-recipient, we need to first encrypt the message
        // using the first recipient's session to get the message type and serialized form
        // Then we create a USMC and use it for multi-recipient encryption

        // Encrypt with the first recipient to get the ciphertext message
        let first_address =
            recipients
                .first()
                .ok_or_else(|| ServiceError::InvalidFrame {
                    reason: "no recipients provided",
                })?;

        let padded_content =
            add_padding(sessions[0].session_version()?, content)?;

        let message = message_encrypt(
            &padded_content,
            first_address,
            &mut self.protocol_store.clone(),
            &mut self.protocol_store.clone(),
            SystemTime::now(),
            csprng,
        )
        .await?;

        // Build the UnidentifiedSenderMessageContent from the encrypted message
        let usmc = UnidentifiedSenderMessageContent::new(
            message.message_type(),
            sender_certificate.clone(),
            message.serialize().to_vec(),
            ContentHint::Default,
            None, // group_id
        )?;

        // Collect references for the encryption call
        let address_refs: Vec<&ProtocolAddress> = recipients.iter().collect();
        let session_refs: Vec<&SessionRecord> = sessions.iter().collect();

        // Encrypt using multi-recipient sealed sender
        let payload = sealed_sender_multi_recipient_encrypt(
            &address_refs,
            &session_refs,
            excluded_recipients,
            &usmc,
            &self.protocol_store,
            csprng,
        )
        .await?;

        Ok(payload)
    }

    /// Encrypt a message for a group using Sender Keys.
    ///
    /// This method uses Sender Keys (DistributionId) for group encryption, which is
    /// the correct approach for multi-recipient group messages. Unlike `encrypt_for_multi_recipient`
    /// which uses Double Ratchet sessions, this method:
    ///
    /// 1. Uses a shared symmetric key (Sender Key) for all recipients
    /// 2. Creates a single `SenderKeyMessage` that all recipients can decrypt
    /// 3. Wraps it in sealed sender for anonymous delivery
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender's protocol address
    /// * `distribution_id` - UUID identifying the sender key group (derived from group master key)
    /// * `recipients` - List of protocol addresses for each recipient (for sealed sender envelope)
    /// * `sender_certificate` - The sender certificate for anonymous delivery
    /// * `content` - The plaintext content to encrypt
    /// * `excluded_recipients` - Service IDs to exclude (typically just the sender)
    /// * `csprng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// Returns the encrypted multi-recipient payload on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn encrypt_for_group<R: Rng + CryptoRng>(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        recipients: &[ProtocolAddress],
        sender_certificate: &SenderCertificate,
        content: &[u8],
        excluded_recipients: Vec<ServiceId>,
        csprng: &mut R,
    ) -> Result<Vec<u8>, ServiceError> {
        // Encrypt the content using Sender Keys (symmetric encryption)
        // This creates a SenderKeyMessage that is the SAME for all recipients
        let sender_key_message = group_encrypt(
            &mut self.protocol_store,
            sender,
            distribution_id,
            content,
            csprng,
        )
        .await
        .map_err(ServiceError::from)?;

        // Build the UnidentifiedSenderMessageContent with the SenderKeyMessage
        // Note: SenderKeyMessage has its own padding, so we don't add padding here
        let usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            sender_certificate.clone(),
            sender_key_message.serialized().to_vec(),
            ContentHint::Default,
            None, // group_id
        )?;

        // Load sessions for recipients (needed for sealed_sender_multi_recipient_encrypt)
        // The sessions are only used for their remote_registration_id field,
        // NOT for encryption (we already encrypted with sender keys)
        let mut sessions: Vec<SessionRecord> =
            Vec::with_capacity(recipients.len());
        for address in recipients {
            let session = self
                .protocol_store
                .load_session(address)
                .await?
                .ok_or_else(|| {
                    SignalProtocolError::SessionNotFound(address.clone())
                })?;
            sessions.push(session);
        }

        // Collect references for the encryption call
        let address_refs: Vec<&ProtocolAddress> = recipients.iter().collect();
        let session_refs: Vec<&SessionRecord> = sessions.iter().collect();

        // Encrypt using multi-recipient sealed sender
        // This encrypts the USMC with identity keys for anonymous delivery
        let payload = sealed_sender_multi_recipient_encrypt(
            &address_refs,
            &session_refs,
            excluded_recipients,
            &usmc,
            &self.protocol_store,
            csprng,
        )
        .await?;

        Ok(payload)
    }

    /// Create a Sender Key Distribution Message for a group.
    ///
    /// This should be sent to new group members so they can decrypt future
    /// group messages. The distribution message contains the sender key
    /// encrypted with the recipient's identity key.
    ///
    /// # Arguments
    ///
    /// * `sender` - The sender's protocol address
    /// * `distribution_id` - UUID identifying the sender key group
    /// * `csprng` - Cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// Returns a `SenderKeyDistributionMessage` that should be sent to new members.
    pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        csprng: &mut R,
    ) -> Result<SenderKeyDistributionMessage, ServiceError> {
        create_sender_key_distribution_message(
            sender,
            distribution_id,
            &mut self.protocol_store,
            csprng,
        )
        .await
        .map_err(ServiceError::from)
    }
}

struct Plaintext {
    metadata: Metadata,
    data: Vec<u8>,
}

/// Result of decrypting a sealed sender message.
/// This is similar to `SealedSenderDecryptionResult` from libsignal_protocol,
/// but includes a `was_plaintext` flag to track whether the message was sent
/// as plaintext (unencrypted) content.
#[allow(dead_code)]
struct LocalSealedSenderDecryptionResult {
    sender_uuid: String,
    sender_e164: Option<String>,
    device_id: DeviceId,
    message: Vec<u8>,
    /// True if the message was sent as plaintext (CiphertextMessageType::Plaintext)
    was_plaintext: bool,
}

#[expect(clippy::comparison_chain)]
fn add_padding(version: u32, contents: &[u8]) -> Result<Vec<u8>, ServiceError> {
    if version < 2 {
        Err(ServiceError::PaddingVersion(version))
    } else if version == 2 {
        Ok(contents.to_vec())
    } else {
        let message_length = contents.len();
        let message_length_with_terminator = contents.len() + 1;
        let mut message_part_count = message_length_with_terminator / 160;
        if !message_length_with_terminator.is_multiple_of(160) {
            message_part_count += 1;
        }

        let message_length_with_padding = message_part_count * 160;

        let mut buffer = vec![0u8; message_length_with_padding];
        buffer[..message_length].copy_from_slice(contents);
        Iso7816::raw_pad(&mut buffer, message_length);
        Ok(buffer)
    }
}

#[expect(clippy::comparison_chain)]
fn strip_padding_version(
    version: u32,
    contents: &mut Vec<u8>,
) -> Result<(), ServiceError> {
    if version < 2 {
        Err(ServiceError::InvalidFrame {
            reason: "unknown version",
        })
    } else if version == 2 {
        Ok(())
    } else {
        strip_padding(contents)?;
        Ok(())
    }
}

fn strip_padding(contents: &mut Vec<u8>) -> Result<(), ServiceError> {
    let new_length = Iso7816::raw_unpad(contents)?.len();
    contents.resize(new_length, 0);
    Ok(())
}

/// Equivalent of `SignalServiceCipher::getPreferredProtocolAddress`
pub async fn get_preferred_protocol_address<S: SessionStore>(
    session_store: &S,
    address: &ServiceId,
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
#[tracing::instrument(
    skip(
        ciphertext,
        trust_roots,
        identity_store,
        session_store,
        pre_key_store,
        signed_pre_key_store,
        sender_key_store,
        kyber_pre_key_store
    ),
    fields(
        ciphertext = ciphertext.len(),
    )
)]
async fn sealed_sender_decrypt(
    ciphertext: &[u8],
    trust_roots: &[PublicKey],
    timestamp: Timestamp,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: DeviceId,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<LocalSealedSenderDecryptionResult, SignalProtocolError> {
    let usmc =
        sealed_sender_decrypt_to_usmc(ciphertext, identity_store).await?;

    if !usmc
        .sender()?
        .validate_with_trust_roots(trust_roots, timestamp)?
    {
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

    let mut rng = rng();

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );

    let (message, was_plaintext) = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            let decrypted = message_decrypt_signal(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                &mut rng,
            )
            .await?;
            (decrypted, false)
        },
        CiphertextMessageType::PreKey => {
            let ctext = PreKeySignalMessage::try_from(usmc.contents()?)?;
            let decrypted = message_decrypt_prekey(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                kyber_pre_key_store,
                &mut rng,
            )
            .await?;
            (decrypted, false)
        },
        CiphertextMessageType::SenderKey => {
            let decrypted = group_decrypt(
                usmc.contents()?,
                sender_key_store,
                &remote_address,
            )
            .await?;
            (decrypted, false)
        },
        CiphertextMessageType::Plaintext => {
            // Plaintext messages are wrapped in a PlaintextContent protobuf.
            // The PlaintextContent has:
            // - 0xC0 prefix byte (PLAINTEXT_CONTEXT_IDENTIFIER_BYTE)
            // - Content protobuf
            // - 0x80 suffix byte (PADDING_BOUNDARY_BYTE)
            // The body() method returns bytes[1..], which includes Content + 0x80.
            // We must strip the PADDING_BOUNDARY_BYTE to get the valid Content protobuf.
            let plaintext_content =
                PlaintextContent::try_from(usmc.contents()?)?;
            let body = plaintext_content.body();
            // Strip the PADDING_BOUNDARY_BYTE (0x80) from the end
            let content_bytes = &body[..body.len().saturating_sub(1)];
            (content_bytes.to_vec(), true)
        },
    };

    Ok(LocalSealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
        was_plaintext,
    })
}
