use std::{collections::HashSet, time::SystemTime};

use chrono::prelude::*;
use libsignal_core::{curve::CurveError, InvalidDeviceId};
use libsignal_protocol::{
    process_prekey_bundle, Aci, DeviceId, IdentityKey, IdentityKeyPair, Pni,
    ProtocolStore, SenderCertificate, SenderKeyStore, ServiceId,
    SignalProtocolError,
};
use rand::{rng, CryptoRng, Rng};
use tracing::{debug, error, info, trace, warn};
use tracing_futures::Instrument;
use uuid::Uuid;
use zkgroup::GROUP_IDENTIFIER_LEN;

use crate::{
    cipher::{get_preferred_protocol_address, ServiceCipher},
    content::ContentBody,
    proto::{
        attachment_pointer::{
            AttachmentIdentifier, Flags as AttachmentPointerFlags,
        },
        sync_message::{
            self, message_request_response, MessageRequestResponse,
        },
        AttachmentPointer, SyncMessage,
    },
    push_service::*,
    service_address::ServiceIdExt,
    session_store::SessionStoreExt,
    unidentified_access::UnidentifiedAccess,
    utils::{serde_device_id, serde_service_id},
    websocket::{self, SignalWebSocket},
};

pub use crate::proto::ContactDetails;

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPushMessage {
    pub r#type: u32,
    #[serde(with = "serde_device_id")]
    pub destination_device_id: DeviceId,
    pub destination_registration_id: u32,
    pub content: String,
}

#[derive(serde::Serialize, Debug)]
pub struct OutgoingPushMessages {
    #[serde(with = "serde_service_id")]
    pub destination: ServiceId,
    pub timestamp: u64,
    pub messages: Vec<OutgoingPushMessage>,
    pub online: bool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub needs_sync: bool,
}

pub type SendMessageResult = Result<SentMessage, MessageSenderError>;

#[derive(Debug, Clone)]
pub struct SentMessage {
    pub recipient: ServiceId,
    pub used_identity_key: IdentityKey,
    pub unidentified: bool,
    pub needs_sync: bool,
}

/// Attachment specification to be used for uploading.
///
/// Loose equivalent of Java's `SignalServiceAttachmentStream`.
#[derive(Debug, Default)]
pub struct AttachmentSpec {
    pub content_type: String,
    pub length: usize,
    pub file_name: Option<String>,
    pub preview: Option<Vec<u8>>,
    pub voice_note: Option<bool>,
    pub borderless: Option<bool>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub caption: Option<String>,
    pub blur_hash: Option<String>,
}

#[derive(Clone)]
pub struct MessageSender<S> {
    identified_ws: SignalWebSocket<websocket::Identified>,
    unidentified_ws: SignalWebSocket<websocket::Unidentified>,
    service: PushService,
    cipher: ServiceCipher<S>,
    protocol_store: S,
    local_aci: Aci,
    local_pni: Pni,
    aci_identity: IdentityKeyPair,
    pni_identity: Option<IdentityKeyPair>,
    device_id: DeviceId,
}

#[derive(thiserror::Error, Debug)]
pub enum AttachmentUploadError {
    #[error("{0}")]
    ServiceError(#[from] ServiceError),

    #[error("Could not read attachment contents")]
    IoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum MessageSenderError {
    #[error("service error: {0}")]
    ServiceError(#[from] ServiceError),

    #[error("protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),

    #[error("invalid private key: {0}")]
    InvalidPrivateKey(#[from] CurveError),

    #[error("invalid device ID: {0}")]
    InvalidDeviceId(#[from] InvalidDeviceId),

    #[error("Failed to upload attachment {0}")]
    AttachmentUploadError(#[from] AttachmentUploadError),

    #[error("primary device can't send sync message {0:?}")]
    SendSyncMessageError(sync_message::request::Type),

    #[error("Untrusted identity key with {address:?}")]
    UntrustedIdentity { address: ServiceId },

    #[error("Exceeded maximum number of retries")]
    MaximumRetriesLimitExceeded,

    #[error("Proof of type {options:?} required using token {token}")]
    ProofRequired { token: String, options: Vec<String> },

    #[error("Recipient not found: {service_id:?}")]
    NotFound { service_id: ServiceId },

    #[error("no messages were encrypted: this should not really happen and most likely implies a logic error")]
    NoMessagesToSend,
}

pub type GroupV2Id = [u8; GROUP_IDENTIFIER_LEN];

#[derive(Debug)]
pub enum ThreadIdentifier {
    Aci(Uuid),
    Group(GroupV2Id),
}

#[derive(Debug)]
pub struct EncryptedMessages {
    messages: Vec<OutgoingPushMessage>,
    used_identity_key: IdentityKey,
}

impl<S> MessageSender<S>
where
    S: ProtocolStore + SenderKeyStore + SessionStoreExt + Sync + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identified_ws: SignalWebSocket<websocket::Identified>,
        unidentified_ws: SignalWebSocket<websocket::Unidentified>,
        service: PushService,
        cipher: ServiceCipher<S>,
        protocol_store: S,
        local_aci: impl Into<Aci>,
        local_pni: impl Into<Pni>,
        aci_identity: IdentityKeyPair,
        pni_identity: Option<IdentityKeyPair>,
        device_id: DeviceId,
    ) -> Self {
        MessageSender {
            service,
            identified_ws,
            unidentified_ws,
            cipher,
            protocol_store,
            local_aci: local_aci.into(),
            local_pni: local_pni.into(),
            aci_identity,
            pni_identity,
            device_id,
        }
    }

    /// Encrypts and uploads an attachment
    ///
    /// Contents are accepted as an owned, plain text Vec, because encryption happens in-place.
    #[tracing::instrument(skip(self, contents, csprng), fields(size = contents.len()))]
    pub async fn upload_attachment<R: Rng + CryptoRng>(
        &mut self,
        spec: AttachmentSpec,
        mut contents: Vec<u8>,
        csprng: &mut R,
    ) -> Result<AttachmentPointer, AttachmentUploadError> {
        let len = contents.len();
        // Encrypt
        let (key, iv) = {
            let mut key = [0u8; 64];
            let mut iv = [0u8; 16];
            csprng.fill_bytes(&mut key);
            csprng.fill_bytes(&mut iv);
            (key, iv)
        };

        // Padded length uses an exponential bracketting thingy.
        // If you want to see how it looks:
        // https://www.wolframalpha.com/input/?i=plot+floor%281.05%5Eceil%28log_1.05%28x%29%29%29+for+x+from+0+to+5000000
        let padded_len: usize = {
            // Java:
            // return (int) Math.max(541, Math.floor(Math.pow(1.05, Math.ceil(Math.log(size) / Math.log(1.05)))))
            std::cmp::max(
                541,
                1.05f64.powf((len as f64).log(1.05).ceil()).floor() as usize,
            )
        };
        if padded_len < len {
            error!(
                "Padded len {} < len {}. Continuing with a privacy risk.",
                padded_len, len
            );
        } else {
            contents.resize(padded_len, 0);
        }

        tracing::trace_span!("encrypting attachment").in_scope(|| {
            crate::attachment_cipher::encrypt_in_place(iv, key, &mut contents)
        });

        // Request upload attributes
        // TODO: we can actually store the upload spec to be able to resume the upload later
        // if it fails or stalls (= we should at least split the API calls so clients can decide what to do)
        let attachment_upload_form = self
            .service
            .get_attachment_v4_upload_attributes()
            .instrument(tracing::trace_span!("requesting upload attributes"))
            .await?;

        let resumable_upload_url = self
            .service
            .get_attachment_resumable_upload_url(&attachment_upload_form)
            .await?;

        let attachment_digest = self
            .service
            .upload_attachment_v4(
                attachment_upload_form.cdn,
                &resumable_upload_url,
                contents.len() as u64,
                attachment_upload_form.headers,
                &mut std::io::Cursor::new(&contents),
            )
            .await?;

        Ok(AttachmentPointer {
            content_type: Some(spec.content_type),
            key: Some(key.to_vec()),
            size: Some(len as u32),
            // thumbnail: Option<Vec<u8>>,
            digest: Some(attachment_digest.digest),
            file_name: spec.file_name,
            flags: Some(
                if spec.voice_note == Some(true) {
                    AttachmentPointerFlags::VoiceMessage as u32
                } else {
                    0
                } | if spec.borderless == Some(true) {
                    AttachmentPointerFlags::Borderless as u32
                } else {
                    0
                },
            ),
            width: spec.width,
            height: spec.height,
            caption: spec.caption,
            blur_hash: spec.blur_hash,
            upload_timestamp: Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("unix epoch in the past")
                    .as_millis() as u64,
            ),
            cdn_number: Some(attachment_upload_form.cdn),
            attachment_identifier: Some(AttachmentIdentifier::CdnKey(
                attachment_upload_form.key,
            )),
            ..Default::default()
        })
    }

    /// Upload contact details to the CDN
    ///
    /// Returns attachment ID and the attachment digest
    #[tracing::instrument(skip(self, contacts))]
    async fn upload_contact_details<Contacts>(
        &mut self,
        contacts: Contacts,
    ) -> Result<AttachmentPointer, AttachmentUploadError>
    where
        Contacts: IntoIterator<Item = ContactDetails>,
    {
        use prost::Message;
        let mut out = Vec::new();
        for contact in contacts {
            contact
                .encode_length_delimited(&mut out)
                .expect("infallible encoding");
            // XXX add avatar here
        }

        let spec = AttachmentSpec {
            content_type: "application/octet-stream".into(),
            length: out.len(),
            file_name: None,
            preview: None,
            voice_note: None,
            borderless: None,
            width: None,
            height: None,
            caption: None,
            blur_hash: None,
        };
        self.upload_attachment(spec, out, &mut rng()).await
    }

    /// Return whether we have to prepare sync messages for other devices
    ///
    /// - If we are the main registered device, and there are established sub-device sessions (linked clients), return true
    /// - If we are a secondary linked device, return true
    async fn is_multi_device(&self) -> bool {
        if self.device_id == *DEFAULT_DEVICE_ID {
            self.protocol_store
                .get_sub_device_sessions(&self.local_aci.into())
                .await
                .is_ok_and(|s| !s.is_empty())
        } else {
            true
        }
    }

    /// Send a message `content` to a single `recipient`.
    #[tracing::instrument(
        skip(self, unidentified_access, message),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub async fn send_message(
        &mut self,
        recipient: &ServiceId,
        mut unidentified_access: Option<UnidentifiedAccess>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        include_pni_signature: bool,
        online: bool,
    ) -> SendMessageResult {
        let content_body = message.into();
        let message_to_self = recipient == &self.local_aci;
        let sync_message =
            matches!(content_body, ContentBody::SynchronizeMessage(..));
        let is_multi_device = self.is_multi_device().await;

        use crate::proto::data_message::Flags;

        let end_session = match &content_body {
            ContentBody::DataMessage(message) => {
                message.flags == Some(Flags::EndSession as u32)
            },
            _ => false,
        };

        // only send a sync message when sending to self and skip the rest of the process
        if message_to_self && is_multi_device && !sync_message {
            debug!("sending note to self");
            if let Some(sync_message) = self
                .create_multi_device_sent_transcript_content(
                    Some(recipient),
                    content_body,
                    timestamp,
                    None,
                )
            {
                return self
                    .try_send_message(
                        *recipient,
                        None,
                        &sync_message,
                        timestamp,
                        include_pni_signature,
                        online,
                    )
                    .await;
            } else {
                error!("could not create sync message from message to self");
                return SendMessageResult::Err(
                    MessageSenderError::NoMessagesToSend,
                );
            }
        }

        // don't send session enders as sealed sender
        // sync messages are never sent as unidentified (reasons unclear), see: https://github.com/signalapp/Signal-Android/blob/main/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java#L779
        if end_session || sync_message {
            unidentified_access.take();
        }

        // try to send the original message to all the recipient's devices
        let result = self
            .try_send_message(
                *recipient,
                unidentified_access.as_ref(),
                &content_body,
                timestamp,
                include_pni_signature,
                online,
            )
            .await;

        let needs_sync = match &result {
            Ok(SentMessage { needs_sync, .. }) => *needs_sync,
            _ => false,
        };

        if needs_sync || is_multi_device {
            debug!("sending multi-device sync message");
            if let Some(sync) = if sync_message {
                Some(content_body)
            } else {
                self.create_multi_device_sent_transcript_content(
                    Some(recipient),
                    content_body,
                    timestamp,
                    Some(&result),
                )
            } {
                self.try_send_message(
                    self.local_aci.into(),
                    None,
                    &sync,
                    timestamp,
                    false,
                    false,
                )
                .await?;
            } else {
                error!("could not create sync message from a direct message");
            }
        }

        if end_session {
            let n = self.protocol_store.delete_all_sessions(recipient).await?;
            tracing::debug!(
                "ended {} sessions with {}",
                n,
                recipient.raw_uuid()
            );
        }

        result
    }

    /// Send a message to the recipients in a group.
    ///
    /// Recipients are a list of tuples, each containing:
    /// - The recipient's address
    /// - The recipient's unidentified access
    /// - Whether the recipient requires a PNI signature
    #[tracing::instrument(
        skip(self, recipients, message),
        fields(recipients = recipients.as_ref().len()),
    )]
    pub async fn send_message_to_group(
        &mut self,
        recipients: impl AsRef<[(ServiceId, Option<UnidentifiedAccess>, bool)]>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Vec<SendMessageResult> {
        let content_body: ContentBody = message.into();
        let mut results = vec![];

        let mut needs_sync_in_results = false;

        for (recipient, unidentified_access, include_pni_signature) in
            recipients.as_ref()
        {
            let result = self
                .try_send_message(
                    *recipient,
                    unidentified_access.as_ref(),
                    &content_body,
                    timestamp,
                    *include_pni_signature,
                    online,
                )
                .await;

            match result {
                Ok(SentMessage { needs_sync, .. }) if needs_sync => {
                    needs_sync_in_results = true;
                },
                _ => (),
            };

            results.push(result);
        }

        // we only need to send a synchronization message once
        if needs_sync_in_results || self.is_multi_device().await {
            if let Some(sync_message) = self
                .create_multi_device_sent_transcript_content(
                    None,
                    content_body.clone(),
                    timestamp,
                    &results,
                )
            {
                // Note: the result of sending a sync message is not included in results
                // See Signal Android `SignalServiceMessageSender.java:2817`
                if let Err(error) = self
                    .try_send_message(
                        self.local_aci.into(),
                        None,
                        &sync_message,
                        timestamp,
                        false, // XXX: maybe the sync device does want a PNI signature?
                        false,
                    )
                    .await
                {
                    error!(%error, "failed to send a synchronization message");
                }
            } else {
                error!("could not create sync message from a group message")
            }
        }

        results
    }

    /// Send a message (`content`) to an address (`recipient`).
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content_body, recipient),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    async fn try_send_message(
        &mut self,
        recipient: ServiceId,
        mut unidentified_access: Option<&UnidentifiedAccess>,
        content_body: &ContentBody,
        timestamp: u64,
        include_pni_signature: bool,
        online: bool,
    ) -> SendMessageResult {
        trace!("trying to send a message");

        use prost::Message;

        let mut content = content_body.clone().into_proto();
        if include_pni_signature {
            content.pni_signature_message = Some(self.create_pni_signature()?);
        }

        let content_bytes = content.encode_to_vec();

        let mut rng = rng();

        for _ in 0..4u8 {
            let Some(EncryptedMessages {
                messages,
                used_identity_key,
            }) = self
                .create_encrypted_messages(
                    &recipient,
                    unidentified_access.map(|x| &x.certificate),
                    &content_bytes,
                )
                .await?
            else {
                // this can happen for example when a device is primary, without any secondaries
                // and we send a message to ourselves (which is only a SyncMessage { sent: ... })
                // addressed to self
                return Err(MessageSenderError::NoMessagesToSend);
            };

            let messages = OutgoingPushMessages {
                destination: recipient,
                timestamp,
                messages,
                online,
            };

            let send = if let Some(unidentified) = &unidentified_access {
                tracing::debug!("sending via unidentified");
                self.unidentified_ws
                    .send_messages_unidentified(messages, unidentified)
                    .await
            } else {
                tracing::debug!("sending identified");
                self.identified_ws.send_messages(messages).await
            };

            match send {
                Ok(SendMessageResponse { needs_sync }) => {
                    tracing::debug!("message sent!");
                    return Ok(SentMessage {
                        recipient,
                        used_identity_key,
                        unidentified: unidentified_access.is_some(),
                        needs_sync,
                    });
                },
                Err(ServiceError::Unauthorized)
                    if unidentified_access.is_some() =>
                {
                    tracing::trace!("unauthorized error using unidentified; retry over identified");
                    unidentified_access = None;
                },
                Err(ServiceError::MismatchedDevicesException(ref m)) => {
                    tracing::debug!("{:?}", m);
                    for extra_device_id in &m.extra_devices {
                        tracing::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        self.protocol_store
                            .delete_service_addr_device_session(
                                &recipient
                                    .to_protocol_address(*extra_device_id)?,
                            )
                            .await?;
                    }

                    for missing_device_id in &m.missing_devices {
                        tracing::debug!(
                            "creating session with missing device {}",
                            missing_device_id
                        );
                        let remote_address = recipient
                            .to_protocol_address(*missing_device_id)?;
                        let pre_key = self
                            .identified_ws
                            .get_pre_key(&recipient, *missing_device_id)
                            .await?;

                        process_prekey_bundle(
                            &remote_address,
                            &mut self.protocol_store.clone(),
                            &mut self.protocol_store,
                            &pre_key,
                            SystemTime::now(),
                            &mut rng,
                        )
                        .await
                        .map_err(|e| {
                            error!("failed to create session: {}", e);
                            MessageSenderError::UntrustedIdentity {
                                address: recipient,
                            }
                        })?;
                    }
                },
                Err(ServiceError::StaleDevices(ref m)) => {
                    tracing::debug!("{:?}", m);
                    for extra_device_id in &m.stale_devices {
                        tracing::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        self.protocol_store
                            .delete_service_addr_device_session(
                                &recipient
                                    .to_protocol_address(*extra_device_id)?,
                            )
                            .await?;
                    }
                },
                Err(ServiceError::ProofRequiredError(ref p)) => {
                    tracing::debug!("{:?}", p);
                    return Err(MessageSenderError::ProofRequired {
                        token: p.token.clone(),
                        options: p.options.clone(),
                    });
                },
                Err(ServiceError::NotFoundError) => {
                    tracing::debug!("Not found when sending a message");
                    return Err(MessageSenderError::NotFound {
                        service_id: recipient,
                    });
                },
                Err(e) => {
                    tracing::debug!(
                        "Default error handler for ws.send_messages: {}",
                        e
                    );
                    return Err(MessageSenderError::ServiceError(e));
                },
            }
        }

        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    /// Upload contact details to the CDN and send a sync message
    #[tracing::instrument(
        skip(self, unidentified_access, contacts, recipient),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub async fn send_contact_details<Contacts>(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<UnidentifiedAccess>,
        // XXX It may be interesting to use an intermediary type,
        //     instead of ContactDetails directly,
        //     because it allows us to add the avatar content.
        contacts: Contacts,
        online: bool,
        complete: bool,
    ) -> Result<(), MessageSenderError>
    where
        Contacts: IntoIterator<Item = ContactDetails>,
    {
        let ptr = self.upload_contact_details(contacts).await?;

        let msg = SyncMessage {
            contacts: Some(sync_message::Contacts {
                blob: Some(ptr),
                complete: Some(complete),
            }),
            ..SyncMessage::with_padding(&mut rng())
        };

        self.send_sync_message(msg).await?;

        Ok(())
    }

    /// Send `MessageRequestResponse` synchronization message with either a recipient ACI or a GroupV2 ID
    #[tracing::instrument(skip(self), fields(recipient = recipient.service_id_string()))]
    pub async fn send_message_request_response(
        &mut self,
        recipient: &ServiceId,
        thread: &ThreadIdentifier,
        action: message_request_response::Type,
    ) -> Result<(), MessageSenderError> {
        let message_request_response = Some(match thread {
            ThreadIdentifier::Aci(aci) => {
                tracing::debug!(
                    "sending message request response {:?} for recipient {:?}",
                    action,
                    aci
                );
                MessageRequestResponse {
                    thread_aci: Some(aci.to_string()),
                    thread_aci_binary: Some(aci.into_bytes().to_vec()),
                    group_id: None,
                    r#type: Some(action.into()),
                }
            },
            ThreadIdentifier::Group(id) => {
                tracing::debug!(
                    "sending message request response {:?} for group {:?}",
                    action,
                    id
                );
                MessageRequestResponse {
                    thread_aci: None,
                    thread_aci_binary: None,
                    group_id: Some(id.to_vec()),
                    r#type: Some(action.into()),
                }
            },
        });

        let msg = SyncMessage {
            message_request_response,
            ..SyncMessage::with_padding(&mut rng())
        };

        let ts = Utc::now().timestamp_millis() as u64;
        self.send_message(recipient, None, msg, ts, false, false)
            .await?;

        Ok(())
    }

    /// Send a `SyncMessage` to own devices, if any.
    pub async fn send_sync_message(
        &mut self,
        sync: SyncMessage,
    ) -> Result<(), MessageSenderError> {
        if self.is_multi_device().await {
            let content = sync.into();
            let timestamp = Utc::now().timestamp_millis() as u64;
            debug!(
                "sending multi-device sync message with content {content:?}"
            );
            self.try_send_message(
                self.local_aci.into(),
                None,
                &content,
                timestamp,
                false,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Send a `SyncMessage` request message
    #[tracing::instrument(skip(self))]
    pub async fn send_sync_message_request(
        &mut self,
        recipient: &ServiceId,
        request_type: sync_message::request::Type,
    ) -> Result<(), MessageSenderError> {
        if self.device_id == *DEFAULT_DEVICE_ID {
            return Err(MessageSenderError::SendSyncMessageError(request_type));
        }

        let msg = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(request_type.into()),
            }),
            ..SyncMessage::with_padding(&mut rng())
        };
        self.send_sync_message(msg).await?;

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn create_pni_signature(
        &mut self,
    ) -> Result<crate::proto::PniSignatureMessage, MessageSenderError> {
        let mut rng = rng();
        let signature = self
            .pni_identity
            .expect("PNI key set when PNI signature requested")
            .sign_alternate_identity(
                self.aci_identity.identity_key(),
                &mut rng,
            )?;
        Ok(crate::proto::PniSignatureMessage {
            pni: Some(self.local_pni.service_id_binary()),
            signature: Some(signature.into()),
        })
    }

    // Equivalent with `getEncryptedMessages`
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    async fn create_encrypted_messages(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<&SenderCertificate>,
        content: &[u8],
    ) -> Result<Option<EncryptedMessages>, MessageSenderError> {
        let mut messages = vec![];

        let mut devices: HashSet<DeviceId> = self
            .protocol_store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .collect();

        // always send to the primary device no matter what
        devices.insert(*DEFAULT_DEVICE_ID);

        // never try to send messages to the sender device
        match recipient {
            ServiceId::Aci(aci) => {
                if *aci == self.local_aci {
                    devices.remove(&self.device_id);
                }
            },
            ServiceId::Pni(pni) => {
                if *pni == self.local_pni {
                    devices.remove(&self.device_id);
                }
            },
        };

        for device_id in devices {
            trace!("sending message to device {}", device_id);
            // `create_encrypted_message` may fail with `SessionNotFound` if the session is corrupted;
            // see https://github.com/whisperfish/libsignal-client/commit/601454d20.
            // If this happens, delete the session and retry.
            for _attempt in 0..2 {
                match self
                    .create_encrypted_message(
                        recipient,
                        unidentified_access,
                        device_id,
                        content,
                    )
                    .await
                {
                    Ok(message) => {
                        messages.push(message);
                        break;
                    },
                    Err(MessageSenderError::ServiceError(
                        ServiceError::SignalProtocolError(
                            SignalProtocolError::SessionNotFound(addr),
                        ),
                    )) => {
                        // SessionNotFound is returned on certain session corruption.
                        // Since delete_session *creates* a session if it doesn't exist,
                        // the NotFound error is an indicator of session corruption.
                        // Try to delete this session, if it gets succesfully deleted, retry.  Otherwise, fail.
                        tracing::warn!("Potential session corruption for {}, deleting session", addr);
                        match self.protocol_store.delete_session(&addr).await {
                            Ok(()) => continue,
                            Err(error) => {
                                tracing::warn!(%error, %addr, "failed to delete session");
                                return Err(
                                    SignalProtocolError::SessionNotFound(addr)
                                        .into(),
                                );
                            },
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
        }

        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EncryptedMessages {
                messages,
                used_identity_key: self
                    .protocol_store
                    .get_identity(
                        &recipient.to_protocol_address(*DEFAULT_DEVICE_ID),
                    )
                    .await?
                    .ok_or(MessageSenderError::UntrustedIdentity {
                        address: *recipient,
                    })?,
            }))
        }
    }

    /// Equivalent to `getEncryptedMessage`
    ///
    /// When no session with the recipient exists, we need to create one.
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub(crate) async fn create_encrypted_message(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<&SenderCertificate>,
        device_id: DeviceId,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, MessageSenderError> {
        let recipient_protocol_address =
            recipient.to_protocol_address(device_id);

        tracing::trace!(
            "encrypting message for {}",
            recipient_protocol_address
        );

        // establish a session with the recipient/device if necessary
        // no need to establish a session with ourselves (and our own current device)
        if self
            .protocol_store
            .load_session(&recipient_protocol_address)
            .await?
            .is_none()
        {
            info!(
                "establishing new session with {}",
                recipient_protocol_address
            );
            let pre_keys = match self
                .identified_ws
                .get_pre_keys(recipient, device_id)
                .await
            {
                Ok(ok) => {
                    tracing::trace!("Get prekeys OK");
                    ok
                },
                Err(ServiceError::NotFoundError) => {
                    return Err(MessageSenderError::NotFound {
                        service_id: *recipient,
                    });
                },
                Err(e) => Err(e)?,
            };

            let mut rng = rng();

            for pre_key_bundle in pre_keys {
                if recipient == &self.local_aci
                    && self.device_id == pre_key_bundle.device_id()?
                {
                    trace!("not establishing a session with myself!");
                    continue;
                }

                let pre_key_address = get_preferred_protocol_address(
                    &self.protocol_store,
                    recipient,
                    pre_key_bundle.device_id()?,
                )
                .await?;

                process_prekey_bundle(
                    &pre_key_address,
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store,
                    &pre_key_bundle,
                    SystemTime::now(),
                    &mut rng,
                )
                .await?;
            }
        }

        let message = self
            .cipher
            .encrypt(
                &recipient_protocol_address,
                unidentified_access,
                content,
                &mut rng(),
            )
            .instrument(tracing::trace_span!("encrypting message"))
            .await?;

        Ok(message)
    }

    fn create_multi_device_sent_transcript_content<'a>(
        &mut self,
        recipient: Option<&ServiceId>,
        content_body: ContentBody,
        timestamp: u64,
        send_message_results: impl IntoIterator<Item = &'a SendMessageResult>,
    ) -> Option<ContentBody> {
        use sync_message::sent::UnidentifiedDeliveryStatus;
        let (message, edit_message) = match content_body {
            ContentBody::DataMessage(m) => (Some(m), None),
            ContentBody::EditMessage(m) => (None, Some(m)),
            _ => return None,
        };
        let unidentified_status: Vec<UnidentifiedDeliveryStatus> =
            send_message_results
                .into_iter()
                .filter_map(|result| result.as_ref().ok())
                .map(|sent| {
                    let SentMessage {
                        recipient,
                        unidentified,
                        used_identity_key,
                        ..
                    } = sent;
                    UnidentifiedDeliveryStatus {
                        destination_service_id: Some(
                            recipient.service_id_string(),
                        ),
                        destination_service_id_binary: Some(
                            recipient.service_id_binary(),
                        ),
                        unidentified: Some(*unidentified),
                        destination_pni_identity_key: Some(
                            used_identity_key.serialize().into(),
                        ),
                    }
                })
                .collect();
        Some(ContentBody::SynchronizeMessage(SyncMessage {
            sent: Some(sync_message::Sent {
                destination_service_id: recipient
                    .map(ServiceId::service_id_string),
                destination_e164: None,
                expiration_start_timestamp: message
                    .as_ref()
                    .and_then(|m| m.expire_timer)
                    .map(|_| timestamp),
                message,
                edit_message,
                timestamp: Some(timestamp),
                unidentified_status,
                ..Default::default()
            }),
            ..SyncMessage::with_padding(&mut rng())
        }))
    }
}
