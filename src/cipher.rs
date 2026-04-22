use std::{convert::TryFrom, fmt, time::SystemTime};

use aes::cipher::block_padding::{Iso7816, RawPadding};
use base64::prelude::*;
use libsignal_core::ServiceIdKind;
use libsignal_protocol::{
    group_decrypt, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, process_sender_key_distribution_message,
    sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
    CiphertextMessageType, DeviceId, IdentityKeyStore, KyberPreKeyStore,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, ProtocolStore,
    PublicKey, SealedSenderDecryptionResult, SenderCertificate,
    SenderKeyDistributionMessage, SenderKeyStore, ServiceId, SessionStore,
    SignalMessage, SignalProtocolError, SignedPreKeyStore, Timestamp,
    UnidentifiedSenderMessageContent,
};
use prost::Message;
use rand::{rng, CryptoRng, Rng};
use uuid::Uuid;

use crate::{
    content::{Content, Metadata},
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
                    tracing::warn!(
                        ?envelope,
                        "Received a decryption error message: {}.",
                        String::from_utf8_lossy(decryption_error_message)
                    );
                } else {
                    tracing::error!(
                        ?envelope,
                        "Received a plaintext envelope with a non-decryption error message."
                    );
                    return Ok(None);
                }
            }

            if message.sync_message.is_some()
                && plaintext.metadata.sender.aci().map(Uuid::from)
                    != Some(local_service.raw_uuid())
                && local_service.kind() == ServiceIdKind::Aci
            {
                tracing::warn!("Source is not ourself.");
                return Ok(None);
            }

            if let Some(bytes) = &message.sender_key_distribution_message {
                let skdm = SenderKeyDistributionMessage::try_from(&bytes[..])?;
                process_sender_key_distribution_message(
                    &plaintext.metadata.protocol_address()?,
                    &skdm,
                    &mut self.protocol_store,
                )
                .await?;

                match Content::from_proto(message, plaintext.metadata) {
                    Err(ServiceError::UnsupportedContent) => {
                        tracing::trace!("Sender key distribution message without additional content");
                        return Ok(None);
                    },
                    content => return Ok(Some(content?)),
                }
            }
            let content = Content::from_proto(message, plaintext.metadata);
            Ok(Some(content?))
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

        if destination_service_id.kind() == ServiceIdKind::Pni
            && envelope.source_service_id.is_none()
        {
            tracing::warn!("received sealed sender message to our PNI; ignoring invalid message");
            return Err(ServiceError::InvalidFrame {
                reason: "sealed sender received on our PNI",
            });
        }

        // TODO: let chain in edition 2024
        if let Some(source_service_id) = envelope.parse_source_service_id() {
            if source_service_id.kind() == ServiceIdKind::Pni
                && envelope.r#type() != Type::ServerDeliveryReceipt
            {
                tracing::warn!("got a message from a PNI that was not a ServerDeliveryReceipt; ignoring invalid message");
                return Err(ServiceError::InvalidFrame {
                    reason: "PNI received a non-ServerDeliveryReceipt",
                });
            }
        }

        use crate::proto::envelope::Type;
        let plaintext = match envelope.r#type() {
            Type::PrekeyBundle => {
                let sender = get_preferred_protocol_address(
                    &self.protocol_store,
                    &envelope
                        .parse_source_service_id()
                        .expect("prekey bundle format"),
                    envelope.source_device().try_into()?,
                )
                .await?;
                let metadata = Metadata {
                    destination: envelope
                        .parse_destination_service_id()
                        .expect("prekey bundle format"),
                    sender: envelope
                        .parse_source_service_id()
                        .expect("prekey bundle format"),
                    sender_device: envelope.source_device().try_into()?,
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: false,

                    server_guid,
                };

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
                    destination: envelope
                        .parse_destination_service_id()
                        .expect("plaintext content format"),
                    sender: envelope
                        .parse_source_service_id()
                        .expect("plaintext content format"),
                    sender_device: envelope.source_device().try_into()?,
                    timestamp: envelope.server_timestamp(),
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: true,

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
                    &envelope
                        .parse_source_service_id()
                        .expect("ciphertext envelope format"),
                    envelope.source_device().try_into()?,
                )
                .await?;
                let metadata = Metadata {
                    destination: envelope
                        .parse_destination_service_id()
                        .expect("ciphertext envelope format"),
                    sender: envelope
                        .parse_source_service_id()
                        .expect("ciphertext envelope format"),
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
                let SealedSenderDecryptionResult {
                    sender_uuid,
                    sender_e164: _,
                    device_id,
                    mut message,
                } = sealed_sender_decrypt(
                    ciphertext,
                    &self.trust_roots,
                    Timestamp::from_epoch_millis(envelope.timestamp()),
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
                    destination: envelope
                        .parse_destination_service_id()
                        .expect("unidentified sender envelope format"),
                    sender,
                    sender_device: device_id,
                    timestamp: envelope.timestamp(),
                    unidentified_sender: true,
                    needs_receipt,
                    was_plaintext: false,

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
}

struct Plaintext {
    metadata: Metadata,
    data: Vec<u8>,
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
            // Sealed sender envelope wrapping a PlaintextContent, used by
            // recipients to send a DecryptionErrorMessage back to the sender
            // when their local session state is out of sync and they need a
            // new session established. Without this branch the envelope is
            // dropped and the sender never learns to reset the session,
            // leaving the two parties stuck in a decryption-failure loop.
            //
            // The PlaintextContent wire format is:
            //   0xC0 (identifier) | Content proto encoding | 0x80 (pad) | 0x00*
            // Strip the 0xC0 prefix here; the caller's strip_padding() removes
            // the 0x80-terminated ISO7816 padding, leaving the raw Content
            // proto bytes that the existing envelope pipeline already decodes
            // into ContentBody::DecryptionErrorMessage via Content::from_proto.
            let contents = usmc.contents()?;
            if contents.first() != Some(&0xC0) {
                return Err(SignalProtocolError::InvalidMessage(
                    CiphertextMessageType::Plaintext,
                    "sealed sender PlaintextContent missing identifier byte",
                ));
            }
            contents[1..].to_vec()
        },
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}

#[cfg(test)]
mod tests {
    use libsignal_protocol::{
        ContentHint, DecryptionErrorMessage, IdentityKeyPair,
        InMemSignalProtocolStore, KeyPair, SenderCertificate, ServerCertificate,
        Timestamp,
    };
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;
    use crate::content::ContentBody;

    /// Round-trip a sealed-sender USMC whose inner message type is
    /// CiphertextMessageType::Plaintext (the wrapper Signal clients use for
    /// DecryptionErrorMessage session-restart requests) and verify that the
    /// raw Content proto bytes fall out the other side with the trailing
    /// 0x80 boundary byte intact for strip_padding() to consume.
    ///
    /// Before the fix this returned
    /// `InvalidMessage(Plaintext, "unexpected message type ...")` and the
    /// envelope was dropped, leaving sender and recipient stuck.
    #[tokio::test]
    async fn sealed_sender_plaintext_usmc_returns_content_proto(
    ) -> Result<(), SignalProtocolError> {
        let mut rng = OsRng.unwrap_err();

        // Certificate chain so UnidentifiedSenderMessageContent::new's sender
        // cert field verifies structurally. We don't feed the result through
        // trust-root validation (that runs upstream in sealed_sender_decrypt),
        // so any valid chain works.
        let trust_root = KeyPair::generate(&mut rng);
        let server_key = KeyPair::generate(&mut rng);
        let server_cert = ServerCertificate::new(
            1,
            server_key.public_key,
            &trust_root.private_key,
            &mut rng,
        )?;

        let sender_identity = KeyPair::generate(&mut rng);
        let sender_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f";
        let sender_e164 = "+14151111111";
        let sender_device: DeviceId = 1u32.try_into()
            .expect("1 is a valid device id");
        let sender_cert = SenderCertificate::new(
            sender_uuid.to_string(),
            Some(sender_e164.to_string()),
            sender_identity.public_key,
            sender_device,
            Timestamp::from_epoch_millis(1605722925000),
            server_cert,
            &server_key.private_key,
            &mut rng,
        )?;

        // Real DecryptionErrorMessage payload — build via SenderKey so we
        // don't need a concrete SignalMessage/PreKeySignalMessage to seed
        // for_original's ratchet-key extraction. The DEM contents don't
        // matter for what this test asserts; we just want a byte string
        // that DecryptionErrorMessage::decode will accept so Content::from_proto
        // unambiguously lands in the DecryptionErrorMessage arm.
        let dem = DecryptionErrorMessage::for_original(
            &[],
            CiphertextMessageType::SenderKey,
            Timestamp::from_epoch_millis(1),
            1,
        )?;
        let dem_bytes = dem.serialized().to_vec();
        let content_proto = crate::proto::Content {
            decryption_error_message: Some(dem_bytes.clone()),
            ..Default::default()
        };
        let content_proto_bytes = content_proto.encode_to_vec();

        let mut plaintext_content = Vec::with_capacity(content_proto_bytes.len() + 2);
        plaintext_content.push(0xC0);
        plaintext_content.extend_from_slice(&content_proto_bytes);
        plaintext_content.push(0x80);

        let usmc = UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::Plaintext,
            sender_cert,
            plaintext_content,
            ContentHint::Default,
            None,
        )?;

        // Plaintext arm doesn't touch the session/pre-key/sender-key stores,
        // but the function signature requires them; an empty InMem store
        // satisfies the trait objects.
        let store = InMemSignalProtocolStore::new(
            IdentityKeyPair::generate(&mut rng),
            0x4000,
        )?;
        let remote_address = ProtocolAddress::new(
            sender_uuid.to_string(),
            sender_device,
        );
        let local_address = ProtocolAddress::new(
            "12345678-1234-1234-1234-123456789012".to_string(),
            sender_device,
        );

        let result = sealed_sender_decrypt_with_validated_usmc(
            &usmc,
            &remote_address,
            &local_address,
            &mut store.clone(),
            &mut store.clone(),
            &mut store.clone(),
            &mut store.clone(),
            &mut store.clone(),
            &mut store.clone(),
        )
        .await?;

        // The returned message should be the Content proto bytes followed
        // by the 0x80 pad byte — the 0xC0 identifier byte is stripped here
        // and the caller's strip_padding() strips the trailing 0x80.
        assert_eq!(result.sender_uuid, sender_uuid);
        assert_eq!(result.device_id, sender_device);

        let expected_len = content_proto_bytes.len() + 1;
        assert_eq!(result.message.len(), expected_len);
        assert_eq!(&result.message[..content_proto_bytes.len()], &content_proto_bytes[..]);
        assert_eq!(result.message.last(), Some(&0x80));

        // Simulate every step open_envelope() runs downstream of decrypt():
        // strip_padding -> Content::decode -> Content::from_proto. If any of
        // these fails on our output, the fix doesn't actually reach
        // registered.rs's DecryptionErrorMessage handler in production.
        let mut message = result.message;
        strip_padding(&mut message).expect("0x80 boundary byte strips cleanly");

        let decoded = crate::proto::Content::decode(message.as_slice())
            .expect("Content proto decodes after strip_padding");
        assert_eq!(decoded.decryption_error_message.as_deref(), Some(&dem_bytes[..]));

        // Build a Metadata matching what decrypt() would produce for the
        // sealed-sender branch (was_plaintext: false — we deliberately don't
        // change that, and the test guards against a downstream regression
        // where from_proto would depend on it).
        let metadata = Metadata {
            destination: ServiceId::parse_from_service_id_string(
                "12345678-1234-1234-1234-123456789012",
            )
            .expect("valid destination"),
            sender: ServiceId::parse_from_service_id_string(sender_uuid)
                .expect("valid sender"),
            sender_device,
            timestamp: 0,
            needs_receipt: true,
            unidentified_sender: true,
            was_plaintext: false,
            server_guid: None,
        };
        let content = Content::from_proto(decoded, metadata)
            .expect("Content::from_proto accepts a real DEM payload");
        assert!(
            matches!(content.body, ContentBody::DecryptionErrorMessage(_)),
            "expected DecryptionErrorMessage body, got {:?}",
            content.body,
        );

        Ok(())
    }
}
