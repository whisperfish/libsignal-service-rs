use std::{collections::HashSet, time::SystemTime};

use chrono::prelude::*;
use libsignal_protocol::{
    process_prekey_bundle, DeviceId, ProtocolStore, SenderCertificate,
    SenderKeyStore, SignalProtocolError,
};
use rand::{CryptoRng, Rng};
use tracing::{info, trace};
use tracing_futures::Instrument;
use uuid::Uuid;

use crate::{
    cipher::{get_preferred_protocol_address, ServiceCipher},
    content::ContentBody,
    proto::{
        attachment_pointer::AttachmentIdentifier,
        attachment_pointer::Flags as AttachmentPointerFlags, sync_message,
        AttachmentPointer, SyncMessage,
    },
    push_service::*,
    session_store::SessionStoreExt,
    unidentified_access::UnidentifiedAccess,
    websocket::SignalWebSocket,
    ServiceAddress,
};

pub use crate::proto::{ContactDetails, GroupDetails};

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPushMessage {
    pub r#type: u32,
    pub destination_device_id: u32,
    pub destination_registration_id: u32,
    pub content: String,
}

#[derive(serde::Serialize, Debug)]
pub struct OutgoingPushMessages {
    pub recipient: ServiceAddress,
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
    pub recipient: ServiceAddress,
    pub unidentified: bool,
    pub needs_sync: bool,
}

/// Attachment specification to be used for uploading.
///
/// Loose equivalent of Java's `SignalServiceAttachmentStream`.
#[derive(Debug)]
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

/// Equivalent of Java's `SignalServiceMessageSender`.
#[derive(Clone)]
pub struct MessageSender<Service, S, R> {
    identified_ws: SignalWebSocket,
    unidentified_ws: SignalWebSocket,
    service: Service,
    cipher: ServiceCipher<S, R>,
    csprng: R,
    protocol_store: S,
    local_address: ServiceAddress,
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
    #[error("{0}")]
    ServiceError(#[from] ServiceError),
    #[error("protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),
    #[error("Failed to upload attachment {0}")]
    AttachmentUploadError(#[from] AttachmentUploadError),

    #[error("Untrusted identity key with {address:?}")]
    UntrustedIdentity { address: ServiceAddress },

    #[error("Exceeded maximum number of retries")]
    MaximumRetriesLimitExceeded,

    #[error("Proof of type {options:?} required using token {token}")]
    ProofRequired { token: String, options: Vec<String> },

    #[error("Recipient not found: {uuid}")]
    NotFound { uuid: Uuid },
}

impl<Service, S, R> MessageSender<Service, S, R>
where
    Service: PushService + Clone,
    S: ProtocolStore + SenderKeyStore + SessionStoreExt + Sync + Clone,
    R: Rng + CryptoRng + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identified_ws: SignalWebSocket,
        unidentified_ws: SignalWebSocket,
        service: Service,
        cipher: ServiceCipher<S, R>,
        csprng: R,
        protocol_store: S,
        local_address: ServiceAddress,
        device_id: DeviceId,
    ) -> Self {
        MessageSender {
            service,
            identified_ws,
            unidentified_ws,
            cipher,
            csprng,
            protocol_store,
            local_address,
            device_id,
        }
    }

    /// Encrypts and uploads an attachment
    ///
    /// Contents are accepted as an owned, plain text Vec, because encryption happens in-place.
    #[tracing::instrument(skip(self, contents), fields(size = contents.len()))]
    pub async fn upload_attachment(
        &mut self,
        spec: AttachmentSpec,
        mut contents: Vec<u8>,
    ) -> Result<AttachmentPointer, AttachmentUploadError> {
        let len = contents.len();
        // Encrypt
        let (key, iv) = {
            use rand::RngCore;
            let mut key = [0u8; 64];
            let mut iv = [0u8; 16];
            // thread_rng is guaranteed to be cryptographically secure
            rand::thread_rng().fill_bytes(&mut key);
            rand::thread_rng().fill_bytes(&mut iv);
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
            tracing::error!(
                "Padded len {} < len {}. Continuing with a privacy risk.",
                padded_len,
                len
            );
        } else {
            contents.resize(padded_len, 0);
        }

        tracing::trace_span!("encrypting attachment").in_scope(|| {
            crate::attachment_cipher::encrypt_in_place(iv, key, &mut contents)
        });

        // Request upload attributes
        let attrs = self
            .identified_ws
            .get_attachment_v2_upload_attributes()
            .instrument(tracing::trace_span!("requesting upload attributes"))
            .await?;
        let (id, digest) = self
            .service
            .upload_attachment(&attrs, &mut std::io::Cursor::new(&contents))
            .instrument(tracing::trace_span!("Uploading attachment"))
            .await?;

        Ok(AttachmentPointer {
            content_type: Some(spec.content_type),
            key: Some(key.to_vec()),
            size: Some(len as u32),
            // thumbnail: Option<Vec<u8>>,
            digest: Some(digest),
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
            cdn_number: Some(0),
            attachment_identifier: Some(AttachmentIdentifier::CdnId(id)),
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
        self.upload_attachment(spec, out).await
    }

    /// Return whether we have to prepare sync messages for other devices
    ///
    /// - If we are the main registered device, and there are established sub-device sessions (linked clients), return true
    /// - If we are a secondary linked device, return true
    async fn is_multi_device(&self) -> bool {
        if self.device_id == DEFAULT_DEVICE_ID.into() {
            self.protocol_store
                .get_sub_device_sessions(&self.local_address)
                .await
                .map_or(false, |s| !s.is_empty())
        } else {
            true
        }
    }

    /// Send a message `content` to a single `recipient`.
    #[tracing::instrument(
        skip(self, unidentified_access, message),
        fields(unidentified_access = unidentified_access.is_some()),
    )]
    pub async fn send_message(
        &mut self,
        recipient: &ServiceAddress,
        mut unidentified_access: Option<UnidentifiedAccess>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> SendMessageResult {
        let content_body = message.into();

        use crate::proto::data_message::Flags;

        let end_session = match &content_body {
            ContentBody::DataMessage(message) => {
                message.flags == Some(Flags::EndSession as u32)
            },
            _ => false,
        };

        // don't send session enders as sealed sender
        if end_session {
            unidentified_access.take();
        }

        // try to send the original message to all the recipient's devices
        let mut results = vec![
            self.try_send_message(
                *recipient,
                unidentified_access.as_ref(),
                &content_body,
                timestamp,
                online,
            )
            .await,
        ];

        match (&content_body, &results[0]) {
            // if we sent a data message and we have linked devices, we need to send a sync message
            (
                ContentBody::DataMessage(message),
                Ok(SentMessage { needs_sync, .. }),
            ) if *needs_sync || self.is_multi_device().await => {
                tracing::debug!("sending multi-device sync message");
                let sync_message = self
                    .create_multi_device_sent_transcript_content(
                        Some(recipient),
                        Some(message.clone()),
                        timestamp,
                        &results,
                    );
                self.try_send_message(
                    self.local_address,
                    unidentified_access.as_ref(),
                    &sync_message,
                    timestamp,
                    false,
                )
                .await?;
            },
            _ => (),
        }

        if end_session {
            let n = self.protocol_store.delete_all_sessions(recipient).await?;
            tracing::debug!("ended {} sessions with {}", n, recipient.uuid);
        }

        results.remove(0)
    }

    /// Send a message to the recipients in a group.
    #[tracing::instrument(
        skip(self, recipients, self_unidentified_access, message),
        fields(recipients = recipients.as_ref().len()),
    )]
    pub async fn send_message_to_group(
        &mut self,
        recipients: impl AsRef<[(ServiceAddress, Option<UnidentifiedAccess>)]>,
        self_unidentified_access: Option<&UnidentifiedAccess>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Vec<SendMessageResult> {
        let content_body: ContentBody = message.into();
        let mut results = vec![];

        let message = match &content_body {
            ContentBody::DataMessage(m) => Some(m.clone()),
            _ => None,
        };

        let recipients = recipients.as_ref();
        let mut needs_sync_in_results = false;
        for (recipient, unidentified_access) in recipients.iter() {
            let result = self
                .try_send_message(
                    *recipient,
                    unidentified_access.as_ref(),
                    &content_body,
                    timestamp,
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

        if needs_sync_in_results && message.is_none() {
            // XXX: does this happen?
            tracing::warn!(
                "Server claims need sync, but not sending datamessage."
            );
        }

        // we only need to send a synchronization message once
        if let Some(message) = message {
            if needs_sync_in_results || self.is_multi_device().await {
                let sync_message = self
                    .create_multi_device_sent_transcript_content(
                        None,
                        Some(message),
                        timestamp,
                        &results,
                    );

                let result = self
                    .try_send_message(
                        self.local_address,
                        self_unidentified_access,
                        &sync_message,
                        timestamp,
                        false,
                    )
                    .await;

                results.push(result);
            }
        }

        results
    }

    /// Send a message (`content`) to an address (`recipient`).
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content_body),
        fields(unidentified_access = unidentified_access.is_some()),
    )]
    async fn try_send_message(
        &mut self,
        recipient: ServiceAddress,
        mut unidentified_access: Option<&UnidentifiedAccess>,
        content_body: &ContentBody,
        timestamp: u64,
        online: bool,
    ) -> SendMessageResult {
        use prost::Message;

        let content = content_body.clone().into_proto();

        let content_bytes = content.encode_to_vec();

        for _ in 0..4u8 {
            let messages = self
                .create_encrypted_messages(
                    &recipient,
                    unidentified_access.map(|x| &x.certificate),
                    &content_bytes,
                )
                .await?;

            let messages = OutgoingPushMessages {
                recipient,
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
                                    .to_protocol_address(*extra_device_id),
                            )
                            .await?;
                    }

                    for missing_device_id in &m.missing_devices {
                        tracing::debug!(
                            "creating session with missing device {}",
                            missing_device_id
                        );
                        let remote_address =
                            recipient.to_protocol_address(*missing_device_id);
                        let pre_key = self
                            .service
                            .get_pre_key(&recipient, *missing_device_id)
                            .await?;

                        process_prekey_bundle(
                            &remote_address,
                            &mut self.protocol_store.clone(),
                            &mut self.protocol_store,
                            &pre_key,
                            SystemTime::now(),
                            &mut self.csprng,
                        )
                        .await
                        .map_err(|e| {
                            tracing::error!("failed to create session: {}", e);
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
                                    .to_protocol_address(*extra_device_id),
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
                        uuid: recipient.uuid,
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
        skip(self, unidentified_access, contacts),
        fields(unidentified_access = unidentified_access.is_some()),
    )]
    pub async fn send_contact_details<Contacts>(
        &mut self,
        recipient: &ServiceAddress,
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
            ..SyncMessage::with_padding()
        };

        self.send_message(
            recipient,
            unidentified_access,
            msg,
            Utc::now().timestamp_millis() as u64,
            online,
        )
        .await?;

        Ok(())
    }

    // Equivalent with `getEncryptedMessages`
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some()),
    )]
    async fn create_encrypted_messages(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&SenderCertificate>,
        content: &[u8],
    ) -> Result<Vec<OutgoingPushMessage>, MessageSenderError> {
        let mut messages = vec![];

        let mut devices: HashSet<DeviceId> = self
            .protocol_store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .map(DeviceId::from)
            .collect();

        // always send to the primary device no matter what
        devices.insert(DEFAULT_DEVICE_ID.into());

        // never try to send messages to the sender device
        if recipient.aci() == self.local_address.aci() {
            devices.remove(&self.device_id);
        }

        for device_id in devices {
            trace!("sending message to device {}", device_id);
            messages.push(
                self.create_encrypted_message(
                    recipient,
                    unidentified_access,
                    device_id,
                    content,
                )
                .await?,
            )
        }

        Ok(messages)
    }

    /// Equivalent to `getEncryptedMessage`
    ///
    /// When no session with the recipient exists, we need to create one.
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some()),
    )]
    async fn create_encrypted_message(
        &mut self,
        recipient: &ServiceAddress,
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
                .service
                .get_pre_keys(recipient, device_id.into())
                .await
            {
                Ok(ok) => {
                    tracing::trace!("Get prekeys OK");
                    ok
                },
                Err(ServiceError::NotFoundError) => {
                    return Err(MessageSenderError::NotFound {
                        uuid: recipient.uuid,
                    });
                },
                Err(e) => Err(e)?,
            };

            for pre_key_bundle in pre_keys {
                if recipient == &self.local_address
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
                    &mut self.csprng,
                )
                .await?;
            }
        }

        let message = self
            .cipher
            .encrypt(&recipient_protocol_address, unidentified_access, content)
            .instrument(tracing::trace_span!("encrypting message"))
            .await?;

        Ok(message)
    }

    fn create_multi_device_sent_transcript_content(
        &self,
        recipient: Option<&ServiceAddress>,
        data_message: Option<crate::proto::DataMessage>,
        timestamp: u64,
        send_message_results: &[SendMessageResult],
    ) -> ContentBody {
        use sync_message::sent::UnidentifiedDeliveryStatus;
        let unidentified_status: Vec<UnidentifiedDeliveryStatus> =
            send_message_results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .map(|sent| {
                    let SentMessage {
                        recipient,
                        unidentified,
                        ..
                    } = sent;
                    UnidentifiedDeliveryStatus {
                        destination_service_id: Some(
                            recipient.uuid.to_string(),
                        ),
                        unidentified: Some(*unidentified),
                    }
                })
                .collect();
        ContentBody::SynchronizeMessage(SyncMessage {
            sent: Some(sync_message::Sent {
                destination_service_id: recipient.map(|r| r.uuid.to_string()),
                destination_e164: None,
                expiration_start_timestamp: if data_message
                    .as_ref()
                    .and_then(|m| m.expire_timer)
                    .is_some()
                {
                    Some(timestamp)
                } else {
                    None
                },
                message: data_message,
                timestamp: Some(timestamp),
                unidentified_status,
                ..Default::default()
            }),
            ..SyncMessage::with_padding()
        })
    }
}
