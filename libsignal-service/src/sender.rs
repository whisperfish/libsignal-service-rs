use std::time::SystemTime;

use chrono::prelude::*;
use libsignal_protocol::{
    process_prekey_bundle, IdentityKeyStore, PreKeyStore, ProtocolAddress,
    SessionStore, SignalProtocolError, SignedPreKeyStore,
};
use log::{info, trace};
use rand::{CryptoRng, Rng};

use crate::{
    cipher::{get_preferred_protocol_address, ServiceCipher},
    content::ContentBody,
    proto::{
        attachment_pointer::AttachmentIdentifier,
        attachment_pointer::Flags as AttachmentPointerFlags, sync_message,
        AttachmentPointer, SyncMessage,
    },
    push_service::*,
    sealed_session_cipher::UnidentifiedAccess,
    session_store::SessionStoreExt,
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
pub struct OutgoingPushMessages<'a> {
    pub destination: &'a str,
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
    recipient: ServiceAddress,
    unidentified: bool,
    needs_sync: bool,
}

/// Attachment specification to be used for uploading.
///
/// Loose equivalent of Java's `SignalServiceAttachmentStream`.
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
pub struct MessageSender<Service, S, I, SP, P, R> {
    service: Service,
    cipher: ServiceCipher<S, I, SP, P, R>,
    csprng: R,
    session_store: S,
    identity_key_store: I,
    local_address: ServiceAddress,
    device_id: u32,
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

    #[error("Untrusted identity key with {identifier}")]
    UntrustedIdentity { identifier: String },

    #[error("No pre-key found to establish session with {0:?}")]
    NoPreKey(ServiceAddress),

    #[error("Please try again")]
    TryAgain,

    #[error("Exceeded maximum number of retries")]
    MaximumRetriesLimitExceeded,

    #[error("Network failure sending message to {recipient}")]
    NetworkFailure { recipient: ServiceAddress },

    #[error("Unregistered recipient {recipient}")]
    UnregisteredFailure { recipient: ServiceAddress },

    #[error("Identity verification failure with {recipient}")]
    IdentityFailure { recipient: ServiceAddress },
}

impl<Service, S, I, SP, P, R> MessageSender<Service, S, I, SP, P, R>
where
    Service: PushService + Clone,
    S: SessionStore + SessionStoreExt + Sync + Clone,
    I: IdentityKeyStore + Clone,
    SP: SignedPreKeyStore + Clone,
    P: PreKeyStore + Clone,
    R: Rng + CryptoRng + Clone,
{
    pub fn new(
        service: Service,
        cipher: ServiceCipher<S, I, SP, P, R>,
        csprng: R,
        session_store: S,
        identity_key_store: I,
        local_address: ServiceAddress,
        device_id: u32,
    ) -> Self {
        MessageSender {
            service,
            cipher,
            csprng,
            session_store,
            identity_key_store,
            local_address,
            device_id,
        }
    }

    /// Encrypts and uploads an attachment
    ///
    /// Contents are accepted as an owned, plain text Vec, because encryption happens in-place.
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
            log::error!(
                "Padded len {} < len {}. Continuing with a privacy risk.",
                padded_len,
                len
            );
        } else {
            contents.resize(padded_len, 0);
        }

        crate::attachment_cipher::encrypt_in_place(iv, key, &mut contents);

        // Request upload attributes
        log::trace!("Requesting upload attributes");
        let attrs = self.service.get_attachment_v2_upload_attributes().await?;

        log::trace!("Uploading attachment");
        let (id, digest) = self
            .service
            .upload_attachment(&attrs, &mut std::io::Cursor::new(&contents))
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

    /// Upload group details to the CDN
    ///
    /// Returns attachment ID and the attachment digest
    async fn upload_group_details<Groups>(
        &mut self,
        groups: Groups,
    ) -> Result<AttachmentPointer, AttachmentUploadError>
    where
        Groups: IntoIterator<Item = GroupDetails>,
    {
        use prost::Message;
        let mut out = Vec::new();
        for group in groups {
            group
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

    /// Upload contact details to the CDN
    ///
    /// Returns attachment ID and the attachment digest
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

    /// Send a message `content` to a single `recipient`.
    pub async fn send_message(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
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

        let mut results = vec![
            self.try_send_message(
                recipient.clone(),
                unidentified_access,
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
            ) if *needs_sync => {
                log::debug!("sending multi-device sync message");
                let sync_message = self
                    .create_multi_device_sent_transcript_content(
                        Some(recipient),
                        Some(message.clone()),
                        timestamp,
                        &results,
                    );
                self.try_send_message(
                    (&self.local_address).clone(),
                    None,
                    &sync_message,
                    timestamp,
                    false,
                )
                .await?;
            },
            _ => (),
        }

        if end_session {
            log::debug!("ending session with {}", recipient);
            if let Some(ref uuid) = recipient.uuid {
                self.session_store
                    .delete_all_sessions(&uuid.to_string())
                    .await?;
            }
            if let Some(e164) = recipient.e164() {
                self.session_store.delete_all_sessions(&e164).await?;
            }
        }

        results.remove(0)
    }

    /// Send a message to the recipients in a group.
    pub async fn send_message_to_group(
        &mut self,
        recipients: impl AsRef<[ServiceAddress]>,
        unidentified_access: Option<&UnidentifiedAccess>,
        message: crate::proto::DataMessage,
        timestamp: u64,
        online: bool,
    ) -> Vec<SendMessageResult> {
        let content_body: ContentBody = message.clone().into();
        let mut results = vec![];

        let recipients = recipients.as_ref();
        let mut needs_sync_in_results = false;
        for recipient in recipients.iter() {
            let result = self
                .try_send_message(
                    recipient.clone(),
                    unidentified_access,
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

        // we only need to send a synchronization message once
        if needs_sync_in_results {
            let sync_message = self
                .create_multi_device_sent_transcript_content(
                    None,
                    Some(message.clone()),
                    timestamp,
                    &results,
                );

            let result = self
                .try_send_message(
                    self.local_address.clone(),
                    unidentified_access,
                    &sync_message,
                    timestamp,
                    false,
                )
                .await;

            results.push(result);
        }

        results
    }

    /// Send a message (`content`) to an address (`recipient`).
    async fn try_send_message(
        &mut self,
        recipient: ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        content_body: &ContentBody,
        timestamp: u64,
        online: bool,
    ) -> SendMessageResult {
        use prost::Message;
        let content = content_body.clone().into_proto();
        let content_bytes = content.encode_to_vec();

        for _ in 0..4u8 {
            let messages = self
                .create_encrypted_messages(&recipient, None, &content_bytes)
                .await?;

            let destination = recipient.identifier();
            let messages = OutgoingPushMessages {
                destination: &destination,
                timestamp,
                messages,
                online,
            };

            match self.service.send_messages(messages).await {
                Ok(SendMessageResponse { needs_sync }) => {
                    log::debug!("message sent!");
                    return Ok(SentMessage {
                        recipient,
                        unidentified: unidentified_access.is_some(),
                        needs_sync,
                    });
                },
                Err(ServiceError::MismatchedDevicesException(ref m)) => {
                    log::debug!("{:?}", m);
                    for extra_device_id in &m.extra_devices {
                        log::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        self.session_store
                            .delete_service_addr_device_session(
                                &recipient,
                                *extra_device_id,
                            )
                            .await?;
                    }

                    for missing_device_id in &m.missing_devices {
                        log::debug!(
                            "creating session with missing device {}",
                            missing_device_id
                        );
                        let remote_address = ProtocolAddress::new(
                            recipient.identifier(),
                            *missing_device_id,
                        );
                        let pre_key = self
                            .service
                            .get_pre_key(&recipient, *missing_device_id)
                            .await?;

                        process_prekey_bundle(
                            &remote_address,
                            &mut self.session_store,
                            &mut self.identity_key_store,
                            &pre_key,
                            &mut self.csprng,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            log::error!("failed to create session: {}", e);
                            MessageSenderError::UntrustedIdentity {
                                identifier: recipient.identifier(),
                            }
                        })?;
                    }
                },
                Err(ServiceError::StaleDevices(ref m)) => {
                    log::debug!("{:?}", m);
                    for extra_device_id in &m.stale_devices {
                        log::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        self.session_store
                            .delete_service_addr_device_session(
                                &recipient,
                                *extra_device_id,
                            )
                            .await?;
                    }
                },
                Err(e) => return Err(MessageSenderError::ServiceError(e)),
            }
        }

        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    /// Upload group details to the CDN and send a sync message
    pub async fn send_groups_details<Groups>(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        // XXX It may be interesting to use an intermediary type,
        //     instead of GroupDetails directly,
        //     because it allows us to add the avatar content.
        groups: Groups,
        online: bool,
    ) -> Result<(), MessageSenderError>
    where
        Groups: IntoIterator<Item = GroupDetails>,
    {
        let ptr = self.upload_group_details(groups).await?;

        let msg = SyncMessage {
            groups: Some(sync_message::Groups { blob: Some(ptr) }),
            ..Default::default()
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

    /// Upload contact details to the CDN and send a sync message
    pub async fn send_contact_details<Contacts>(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
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
            ..Default::default()
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
    async fn create_encrypted_messages(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<UnidentifiedAccess>,
        content: &[u8],
    ) -> Result<Vec<OutgoingPushMessage>, MessageSenderError> {
        let mut messages = vec![];

        let myself = recipient.matches(&self.local_address);
        if !myself || unidentified_access.is_some() {
            trace!("sending message to default device");
            messages.push(
                self.create_encrypted_message(
                    recipient,
                    unidentified_access.as_ref(),
                    DEFAULT_DEVICE_ID,
                    content,
                )
                .await?,
            );
        }

        for device_id in
            recipient.sub_device_sessions(&self.session_store).await?
        {
            trace!("sending message to device {}", device_id);
            let ppa = get_preferred_protocol_address(
                &self.session_store,
                recipient,
                device_id,
            )
            .await?;
            if self.session_store.load_session(&ppa, None).await?.is_some() {
                messages.push(
                    self.create_encrypted_message(
                        recipient,
                        unidentified_access.as_ref(),
                        device_id,
                        content,
                    )
                    .await?,
                )
            }
        }

        Ok(messages)
    }

    /// Equivalent to `getEncryptedMessage`
    ///
    /// When no session with the recipient exists, we need to create one.
    async fn create_encrypted_message(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        device_id: u32,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, MessageSenderError> {
        let recipient_address = get_preferred_protocol_address(
            &self.session_store,
            recipient,
            device_id,
        )
        .await?;
        log::trace!("encrypting message for {:?}", recipient_address);

        if self
            .session_store
            .load_session(&recipient_address, None)
            .await?
            .is_none()
        {
            info!("establishing new session with {:?}", recipient_address);
            let pre_keys =
                self.service.get_pre_keys(recipient, device_id).await?;
            for pre_key_bundle in pre_keys {
                if recipient.matches(&self.local_address)
                    && self.device_id == pre_key_bundle.device_id()?
                {
                    trace!("not establishing a session with myself!");
                    continue;
                }

                let pre_key_address = get_preferred_protocol_address(
                    &self.session_store,
                    recipient,
                    pre_key_bundle.device_id()?,
                )
                .await?;

                process_prekey_bundle(
                    &pre_key_address,
                    &mut self.session_store,
                    &mut self.identity_key_store,
                    &pre_key_bundle,
                    &mut self.csprng,
                    None,
                )
                .await?;
            }
        }

        let message = self
            .cipher
            .encrypt(&recipient_address, unidentified_access, content)
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
                        destination_e164: recipient.e164(),
                        destination_uuid: recipient.uuid.map(|s| s.to_string()),
                        unidentified: Some(*unidentified),
                    }
                })
                .collect();
        ContentBody::SynchronizeMessage(SyncMessage {
            sent: Some(sync_message::Sent {
                destination_uuid: recipient
                    .and_then(|r| r.uuid)
                    .map(|u| u.to_string()),
                destination_e164: recipient.and_then(|r| r.e164()),
                message: data_message,
                timestamp: Some(timestamp),
                unidentified_status,
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}
