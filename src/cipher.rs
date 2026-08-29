use std::{convert::TryFrom, fmt, time::SystemTime};

use aes::cipher::block_padding::{Iso7816, Padding};
use base64::prelude::*;
use libsignal_core::ServiceIdKind;
use libsignal_protocol::{
    group_decrypt, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
    CiphertextMessageType, DeviceId, IdentityKeyStore, KyberPreKeyStore,
    PlaintextContent, Pni, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    ProtocolStore, PublicKey, SealedSenderDecryptionResult, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyStore, ServiceId, SessionNotFound,
    SessionStore, SessionUsabilityRequirements, SignalMessage,
    SignalProtocolError, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent,
};
use prost::Message;
use rand::{rng, CryptoRng, Rng};
use uuid::Uuid;

use crate::{
    content::{Content, Metadata},
    envelope::Envelope,
    proto::PniSignatureMessage,
    push_service::{ServiceError, DEFAULT_DEVICE_ID},
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
    local_address: ProtocolAddress,
}

impl<S> fmt::Debug for ServiceCipher<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCipher")
            .field("protocol_store", &"...")
            .field("trust_root", &"...")
            .field("local_address", &self.local_address)
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
                 client_timestamp: {:?}, \
                 content: {} bytes, \
             }}",
            envelope.parse_source_service_id(),
            envelope.source_device_id(),
            envelope.server_guid(),
            envelope.client_timestamp(),
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
        local_address: ProtocolAddress,
    ) -> Self {
        Self {
            protocol_store,
            trust_roots,
            local_address,
        }
    }

    /// Opens ("decrypts") an envelope.
    ///
    /// Envelopes may be empty, in which case this method returns `Ok(None)`
    ///
    /// # PNI signature side-cars
    ///
    /// A side-car is verified during decryption and, when valid, its
    /// PNI is exposed as `Metadata::pni_verified`. A side-car on a message with
    /// no `content` is discarded, with a `tracing::warn!`; upstream Signal
    /// clients only ever attach a side-car alongside `content`, so this path is
    /// unreachable in practice, and wiring it through would change this method's
    /// return type.
    ///
    /// **NOTE**: must process `Metadata::pni_verified` to confirm the sender's
    /// PNI, not the raw side-car message.
    #[tracing::instrument(skip(envelope, csprng), fields(envelope = debug_envelope(&envelope)))]
    pub async fn open_envelope<R: Rng + CryptoRng>(
        &mut self,
        envelope: Envelope,
        csprng: &mut R,
    ) -> Result<Option<Content>, ServiceError> {
        let local_service: ServiceId =
            ServiceId::parse_from_service_id_string(self.local_address.name())
                .expect("valid protocol address name");

        if envelope.content.is_some() {
            let plaintext = self.decrypt(&envelope, csprng).await?;
            let was_plaintext = plaintext.metadata.was_plaintext;

            tracing::Span::current()
                .record("envelope_metadata", plaintext.metadata.to_string());

            // Ingest side-car messages *before* processing content (which possibly triggers an early `return Ok(None)`)

            if let Some(bytes) =
                &plaintext.message.sender_key_distribution_message
            {
                let skdm = SenderKeyDistributionMessage::try_from(&bytes[..])?;
                let sender = plaintext.metadata.protocol_address()?;
                process_sender_key_distribution_message(
                    &sender,
                    &skdm,
                    &mut self.protocol_store,
                )
                .await?;
                tracing::info!(
                    distribution_id = %skdm.distribution_id()?,
                    sender = %sender,
                    "applied sender key distribution message"
                );
            }

            let Some(content) = &plaintext.message.content else {
                // Cheap-out: post-decrypt side-ops are not propagated alongside the
                // Option<Content>, so a content-less message drops its sidecar here.
                // TODO: return a Vec<DecryptPostOp> next to the Option<Content>.
                if let Some(pni) = plaintext.metadata.pni_verified {
                    tracing::warn!(
                        ?pni,
                        "dropped verified PNI signature: content-less message"
                    );
                }
                tracing::warn!("empty decrypted content");
                return Ok(None);
            };

            // Now, process actual content, *after* side-car messages such as SKDM or PNI
            // signatures.

            // Sanity test: if the envelope was plaintext, the message should *only* be a
            // decryption failure error
            if was_plaintext {
                let crate::proto::content::Content::DecryptionErrorMessage(dme) =
                    content
                else {
                    tracing::error!(
                        ?envelope,
                        "Received a plaintext envelope with a non-decryption error message."
                    );
                    return Ok(None);
                };
                tracing::warn!(
                    ?envelope,
                    "Received a decryption error message: {}.",
                    String::from_utf8_lossy(dme)
                );
            }

            if matches!(content, crate::proto::content::Content::SyncMessage(_))
                && plaintext.metadata.sender.aci().map(Uuid::from)
                    != Some(local_service.raw_uuid())
                && local_service.kind() == ServiceIdKind::Aci
            {
                tracing::warn!("Source is not ourself.");
                return Ok(None);
            }

            let content =
                Content::from_proto(plaintext.message, plaintext.metadata);
            Ok(Some(content?))
        } else {
            Ok(None)
        }
    }

    /// Verify a `PniSignatureMessage` sidecar against the sender's stored identity keys.
    async fn verify_pni_signature(
        &self,
        sender: ServiceId,
        sender_device: DeviceId,
        pni_signature: &PniSignatureMessage,
    ) -> Option<Pni> {
        let Some(sender_aci) = sender.aci() else {
            tracing::warn!("ignoring PNI signature: source is not an ACI");
            return None;
        };

        let Some(pni) =
            Pni::parse_from_service_id_binary(pni_signature.pni.as_deref()?)
        else {
            tracing::warn!("ignoring PNI signature: unparseable PNI");
            return None;
        };
        let signature = pni_signature.signature.as_deref()?;

        let aci_address = sender_aci.to_protocol_address(sender_device).ok()?;
        let aci_identity = self
            .protocol_store
            .get_identity(&aci_address)
            .await
            .ok()
            .flatten()?;

        let pni_address = pni.to_protocol_address(sender_device).ok()?;
        let pni_identity =
            match self.protocol_store.get_identity(&pni_address).await {
                Ok(Some(id)) => id,
                _ => {
                    if sender_device == *DEFAULT_DEVICE_ID {
                        tracing::warn!(
                            "ignoring PNI signature: no PNI identity known"
                        );
                        return None;
                    }
                    // The PNI identity is recorded under the primary device.
                    let primary =
                        pni.to_protocol_address(*DEFAULT_DEVICE_ID).ok()?;
                    match self.protocol_store.get_identity(&primary).await {
                        Ok(Some(id)) => id,
                        _ => {
                            tracing::warn!(
                                "ignoring PNI signature: no PNI identity known"
                            );
                            return None;
                        },
                    }
                },
            };

        let verified = pni_identity
            .verify_alternate_identity(&aci_identity, signature)
            .inspect_err(|e| {
                tracing::warn!(?e, "PNI signature verification error");
            })
            .ok()?;

        if verified {
            tracing::info!(
                aci = %sender_aci.service_id_string(),
                pni = %pni.service_id_string(),
                "verified PNI signature"
            );
            Some(pni)
        } else {
            tracing::warn!(
                aci = %sender_aci.service_id_string(),
                pni = %pni.service_id_string(),
                "invalid PNI signature"
            );
            None
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
        let local_service: ServiceId =
            ServiceId::parse_from_service_id_string(self.local_address.name())
                .expect("valid protocol address name");

        let ciphertext = if let Some(msg) = envelope.content.as_ref() {
            msg
        } else {
            return Err(ServiceError::InvalidFrame {
                reason:
                    "envelope should have either a legacy message or content.",
            });
        };

        let server_guid = envelope.parse_server_guid();

        let Some(destination_service_id) =
            envelope.parse_destination_service_id()
        else {
            tracing::warn!(
                "missing destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "missing destination service id",
            });
        };

        if destination_service_id != local_service {
            tracing::warn!(
                "mismatching destination service id; ignoring invalid message."
            );
            return Err(ServiceError::InvalidFrame {
                reason: "mismatch destination service id",
            });
        }

        let source_service_id = envelope.parse_source_service_id();

        if destination_service_id.kind() == ServiceIdKind::Pni
            && source_service_id.is_none()
        {
            tracing::warn!("received sealed sender message to our PNI; ignoring invalid message");
            return Err(ServiceError::InvalidFrame {
                reason: "sealed sender received on our PNI",
            });
        }

        // TODO: let chain in edition 2024
        if let Some(source_service_id) = source_service_id {
            if source_service_id.kind() == ServiceIdKind::Pni
                && envelope.r#type() != Type::ServerDeliveryReceipt
            {
                tracing::warn!("got a message from a PNI that was not a ServerDeliveryReceipt; ignoring invalid message");
                return Err(ServiceError::InvalidFrame {
                    reason: "PNI received a non-ServerDeliveryReceipt",
                });
            }
        }

        // Extract both kinds of timestamps.
        // Note that we do not `?` here, but rather only later, in case we ever have a branch which
        // is not concerned with envelope metadata.
        let client_timestamp = chrono::DateTime::from_timestamp_millis(
            envelope.client_timestamp() as i64,
        )
        .ok_or(ServiceError::InvalidFrame {
            reason: "unparseable timestamp",
        });
        let server_timestamp = chrono::DateTime::from_timestamp_millis(
            envelope.server_timestamp() as i64,
        )
        .ok_or(ServiceError::InvalidFrame {
            reason: "unparseable server timestamp",
        });

        /// Decrypted bytes plus the [`Metadata`] fields that vary by envelope type.
        struct DecryptedPayload {
            data: Vec<u8>,
            sender: ServiceId,
            sender_device: DeviceId,
            was_plaintext: bool,
            unidentified_sender: bool,
            needs_receipt: bool,
        }

        use crate::proto::envelope::Type;
        let parts = match envelope.r#type() {
            Type::PrekeyMessage => {
                let source_service_id = source_service_id
                    .expect("prekey bundle format contains source_service_id");
                let sender_device = envelope.source_device_id().try_into()?;
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &source_service_id,
                    sender_device,
                )
                .await?;

                let mut data = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &self.local_address,
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
                    .ok_or_else(|| {
                        SignalProtocolError::SessionNotFound(
                            SessionNotFound::new(sender, "decrypt"),
                        )
                    })?;

                strip_padding_version(
                    session_record.session_version()?,
                    &mut data,
                )?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device,
                    was_plaintext: false,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::PlaintextContent => {
                tracing::warn!(?envelope, "Envelope with plaintext content.  This usually indicates a decryption retry.");
                let source_service_id = source_service_id
                    .expect("prekey bundle format contains source_service_id");
                // Unsealed envelope wrapping a PlaintextContent.
                // Should contain a DecryptionErrorMessage.
                let plaintext_content =
                    PlaintextContent::try_from(&ciphertext[..])?;
                let mut data = plaintext_content.body().to_vec();
                strip_padding(&mut data)?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device: envelope.source_device_id().try_into()?,
                    was_plaintext: true,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::DoubleRatchet => {
                let source_service_id = source_service_id
                    .expect("prekey bundle format contains source_service_id");
                let sender_device = envelope.source_device_id().try_into()?;
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &source_service_id,
                    sender_device,
                )
                .await?;

                let mut data = message_decrypt_signal(
                    &SignalMessage::try_from(&ciphertext[..])?,
                    &sender,
                    &self.local_address,
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
                    .ok_or_else(|| {
                        SignalProtocolError::SessionNotFound(
                            SessionNotFound::new(sender, "decrypt"),
                        )
                    })?;

                strip_padding_version(
                    session_record.session_version()?,
                    &mut data,
                )?;
                DecryptedPayload {
                    data,
                    sender: source_service_id,
                    sender_device,
                    was_plaintext: false,
                    unidentified_sender: false,
                    needs_receipt: false,
                }
            },
            Type::UnidentifiedSender => {
                let SealedSenderDecryptionResult {
                    sender_uuid,
                    sender_e164: _,
                    device_id,
                    mut message,
                } = sealed_sender_decrypt(
                    ciphertext,
                    &self.trust_roots,
                    Timestamp::from_epoch_millis(envelope.client_timestamp()),
                    None,
                    self.local_address.clone(),
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

                let needs_receipt = if source_service_id.is_some() {
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

                strip_padding(&mut message)?;

                DecryptedPayload {
                    data: message,
                    sender,
                    sender_device: device_id,
                    was_plaintext: false,
                    unidentified_sender: true,
                    needs_receipt,
                }
            },
            _ => {
                // else
                return Err(ServiceError::InvalidFrame {
                    reason: "envelope has unknown type",
                });
            },
        };

        let message = crate::proto::Content::decode(parts.data.as_slice())?;
        let pni_verified = if let Some(msg) = &message.pni_signature_message {
            self.verify_pni_signature(parts.sender, parts.sender_device, msg)
                .await
        } else {
            None
        };
        let metadata = Metadata {
            destination: destination_service_id,
            sender: parts.sender,
            sender_device: parts.sender_device,
            client_timestamp: client_timestamp?,
            server_timestamp: server_timestamp?,
            needs_receipt: parts.needs_receipt,
            unidentified_sender: parts.unidentified_sender,
            was_plaintext: parts.was_plaintext,
            server_guid,
            pni_verified,
        };
        Ok(Plaintext { metadata, message })
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
            SignalProtocolError::SessionNotFound(SessionNotFound::new(
                address.clone(),
                "encrypt",
            ))
        })?;

        let record_usable = session_record
            .has_usable_sender_chain(
                SystemTime::now(),
                SessionUsabilityRequirements::NotStale,
            )
            .unwrap_or(false);
        if !record_usable {
            Err(SignalProtocolError::SessionNotFound(SessionNotFound::new(
                address.clone(),
                "encrypt",
            )))?;
        }

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
                &self.local_address,
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
                CiphertextMessageType::PreKey => Type::PrekeyMessage,
                CiphertextMessageType::Whisper => Type::DoubleRatchet,
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
    message: crate::proto::Content,
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

/// Error thrown when the sealed sending decryption fails.
///
/// The USMC sender field is only populated when the USMC could be validated against the trust roots;
/// hence the sender information can be trusted, give or take an active attacker on the Signal
/// side.
#[derive(thiserror::Error)]
#[error("error: {inner}, usmc: {}", sender.is_some())]
pub struct SealedSenderDecryptionError {
    pub inner: SignalProtocolError,
    pub sender: Option<ProtocolAddress>,
}

impl fmt::Debug for SealedSenderDecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSenderDecryptionError")
            .field("inner", &self.inner)
            .field("sender", &self.sender)
            .finish()
    }
}

impl From<SignalProtocolError> for SealedSenderDecryptionError {
    fn from(e: SignalProtocolError) -> Self {
        SealedSenderDecryptionError {
            inner: e,
            sender: None,
        }
    }
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
    local_address: ProtocolAddress,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<SealedSenderDecryptionResult, SealedSenderDecryptionError> {
    let usmc =
        sealed_sender_decrypt_to_usmc(ciphertext, identity_store).await?;

    if !usmc
        .sender()?
        .validate_with_trust_roots(trust_roots, timestamp)?
    {
        return Err(SignalProtocolError::InvalidSealedSenderMessage(
            "trust root validation failed".to_string(),
        )
        .into());
    }

    let local_service_id =
        ServiceId::parse_from_service_id_string(local_address.name())
            .expect("valid protocol address name");
    let is_local_uuid = local_service_id.raw_uuid()
        == usmc
            .sender()?
            .sender_uuid()?
            .parse::<Uuid>()
            // Validity checked inside certificate checker
            .expect("valid uuid");

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid)
        && usmc.sender()?.sender_device_id()? == local_address.device_id()
    {
        return Err(SignalProtocolError::SealedSenderSelfSend.into());
    }

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );

    sealed_sender_decrypt_with_validated_usmc(
        &usmc,
        &remote_address,
        &local_address,
        identity_store,
        session_store,
        pre_key_store,
        signed_pre_key_store,
        sender_key_store,
        kyber_pre_key_store,
    )
    .await
    .map_err(|inner| SealedSenderDecryptionError {
        inner,
        sender: Some(remote_address),
    })
}

#[allow(clippy::too_many_arguments)]
async fn sealed_sender_decrypt_with_validated_usmc(
    usmc: &UnidentifiedSenderMessageContent,
    remote_address: &ProtocolAddress,
    local_address: &ProtocolAddress,
    identity_store: &mut dyn IdentityKeyStore,
    session_store: &mut dyn SessionStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &mut dyn SignedPreKeyStore,
    sender_key_store: &mut dyn SenderKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
) -> Result<SealedSenderDecryptionResult, SignalProtocolError> {
    let mut rng = rng();

    let message = match usmc.msg_type()? {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            message_decrypt_signal(
                &ctext,
                remote_address,
                local_address,
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
                remote_address,
                local_address,
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
            group_decrypt(usmc.contents()?, sender_key_store, remote_address)
                .await?
        },
        CiphertextMessageType::Plaintext => {
            // Sealed sender envelope wrapping a PlaintextContent.
            // Should contain a DecryptionErrorMessage.
            let plaintext_content =
                PlaintextContent::try_from(usmc.contents()?)?;
            plaintext_content.body().to_vec()
        },
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}
