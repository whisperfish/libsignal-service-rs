use std::time::SystemTime;

use crate::proto::{
    attachment_pointer::AttachmentIdentifier,
    attachment_pointer::Flags as AttachmentPointerFlags, AttachmentPointer,
};

use libsignal_protocol::{Address, SessionBuilder};
use log::{info, trace};

use crate::{
    cipher::ServiceCipher, content::ContentBody, push_service::*,
    sealed_session_cipher::UnidentifiedAccess, ServiceAddress,
};

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPushMessage {
    pub r#type: u32,
    pub destination_device_id: i32,
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

#[derive(Debug, Clone)]
pub struct SendMessageResult {
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
    pub voice_note: bool,
    pub borderless: bool,
    pub width: u32,
    pub height: u32,
    pub caption: Option<String>,
    pub blur_hash: Option<String>,
}

/// Equivalent of Java's `SignalServiceMessageSender`.
#[derive(Clone)]
pub struct MessageSender<Service> {
    service: Service,
    cipher: ServiceCipher,
    device_id: i32,
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
    ProtocolError(#[from] libsignal_protocol::Error),

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

impl<Service> MessageSender<Service>
where
    Service: PushService + Clone,
{
    pub fn new(
        service: Service,
        cipher: ServiceCipher,
        device_id: i32,
    ) -> Self {
        MessageSender {
            service,
            cipher,
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
                if spec.voice_note {
                    AttachmentPointerFlags::VoiceMessage as u32
                } else {
                    0
                } | if spec.borderless {
                    AttachmentPointerFlags::Borderless as u32
                } else {
                    0
                },
            ),
            width: Some(spec.width),
            height: Some(spec.height),
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

    /// Send a message `content` to a single `recipient`.
    pub async fn send_message(
        &mut self,
        recipient: ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        message: crate::proto::DataMessage,
        timestamp: u64,
        online: bool,
    ) -> Result<SendMessageResult, MessageSenderError> {
        let content_body = message.clone().into();

        use crate::proto::data_message::Flags;
        let end_session = match &content_body {
            ContentBody::DataMessage(message) => {
                message.flags == Some(Flags::EndSession as u32)
            }
            _ => false,
        };

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
            Ok(SendMessageResult { needs_sync, .. }) if needs_sync => {
                log::debug!("sending multi-device sync message");
                let sync_message = self
                    .create_multi_device_sent_transcript_content(
                        Some(&recipient),
                        Some(message),
                        timestamp,
                    )?;
                self.try_send_message(
                    (&self.cipher.local_address).clone(),
                    None,
                    &sync_message,
                    timestamp,
                    false,
                )
                .await?;
            }
            _ => (),
        }

        if end_session {
            log::debug!("ending session with {}", recipient);
            if let Some(ref uuid) = recipient.uuid {
                self.cipher.store_context.delete_all_sessions(&uuid)?;
            }
            if let Some(ref e164) = recipient.e164 {
                self.cipher.store_context.delete_all_sessions(&e164)?;
            }
        }

        result
    }

    /// Send a message to the recipients in a group.
    pub async fn send_message_to_group(
        &mut self,
        recipients: Vec<ServiceAddress>,
        unidentified_access: Option<&UnidentifiedAccess>,
        message: crate::proto::DataMessage,
        timestamp: u64,
        online: bool,
    ) -> Result<
        Vec<Result<SendMessageResult, MessageSenderError>>,
        MessageSenderError,
    > {
        // TODO: discuss and fix the rather horrible type above
        let content_body: ContentBody = message.clone().into();

        let mut send_futures = vec![];
        for recipient in recipients.iter() {
            send_futures.push(self.try_send_message(
                recipient.clone(),
                unidentified_access,
                &content_body,
                timestamp,
                online,
            ))
        }

        let results: Vec<Result<SendMessageResult, MessageSenderError>> =
            futures::future::join_all(send_futures).await;
        for result in results.iter() {
            match result {
                Ok(SendMessageResult { needs_sync, .. }) if *needs_sync => {
                    let recipient = match content_body {
                        ContentBody::DataMessage(
                            crate::proto::DataMessage {
                                group, group_v2, ..
                            },
                        ) if group.is_none()
                            && group_v2.is_none()
                            && recipients.len() == 1 =>
                        {
                            Some(&recipients[0])
                        }
                        _ => None,
                    };
                    let sync_message = self
                        .create_multi_device_sent_transcript_content(
                            recipient,
                            Some(message),
                            timestamp,
                        )?;
                    self.try_send_message(
                        self.cipher.local_address.clone(),
                        unidentified_access,
                        &sync_message,
                        timestamp,
                        false,
                    )
                    .await?;

                    return Ok(results);
                }
                _ => (),
            }
        }

        Ok(results)
    }

    /// Send a message (`content`) to an address (`recipient`).
    async fn try_send_message(
        &self,
        recipient: ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        content_body: &ContentBody,
        timestamp: u64,
        online: bool,
    ) -> Result<SendMessageResult, MessageSenderError> {
        use prost::Message;
        let content = content_body.clone().into_proto();
        let mut content_bytes = Vec::with_capacity(content.encoded_len());
        content
            .encode(&mut content_bytes)
            .expect("infallible message encoding");

        for _ in 0..4u8 {
            let messages = self
                .create_encrypted_messages(&recipient, None, &content_bytes)
                .await?;

            let messages = OutgoingPushMessages {
                destination: recipient.identifier(),
                timestamp,
                messages,
                online,
            };

            match self.service.send_messages(messages).await {
                Ok(SendMessageResponse { needs_sync }) => {
                    log::debug!("message sent!");
                    return Ok(SendMessageResult {
                        recipient,
                        unidentified: unidentified_access.is_some(),
                        needs_sync,
                    });
                }
                Err(ServiceError::MismatchedDevicesException(ref m)) => {
                    log::debug!("{:?}", m);
                    for extra_device_id in &m.extra_devices {
                        log::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        if let Some(ref uuid) = recipient.uuid {
                            self.cipher.store_context.delete_session(
                                &libsignal_protocol::Address::new(
                                    uuid,
                                    *extra_device_id,
                                ),
                            )?;
                        }
                        if let Some(ref e164) = recipient.e164 {
                            self.cipher.store_context.delete_session(
                                &libsignal_protocol::Address::new(
                                    &e164,
                                    *extra_device_id,
                                ),
                            )?;
                        }
                    }

                    for missing_device_id in &m.missing_devices {
                        log::debug!(
                            "creating session with missing device {}",
                            missing_device_id
                        );
                        let pre_key = self
                            .service
                            .get_pre_key(
                                &self.cipher.context,
                                &recipient,
                                *missing_device_id,
                            )
                            .await?;
                        SessionBuilder::new(
                            &self.cipher.context,
                            &self.cipher.store_context,
                            &libsignal_protocol::Address::new(
                                &recipient.identifier(),
                                *missing_device_id,
                            ),
                        )
                        .process_pre_key_bundle(&pre_key)
                        .map_err(|e| {
                            log::error!("failed to create session: {}", e);
                            MessageSenderError::UntrustedIdentity {
                                identifier: recipient.identifier().to_string(),
                            }
                        })?;
                    }
                }
                Err(ServiceError::StaleDevices(ref m)) => {
                    log::debug!("{:?}", m);
                    for extra_device_id in &m.stale_devices {
                        log::debug!(
                            "dropping session with device {}",
                            extra_device_id
                        );
                        if let Some(ref uuid) = recipient.uuid {
                            self.cipher.store_context.delete_session(
                                &libsignal_protocol::Address::new(
                                    uuid,
                                    *extra_device_id,
                                ),
                            )?;
                        }
                        if let Some(ref e164) = recipient.e164 {
                            self.cipher.store_context.delete_session(
                                &libsignal_protocol::Address::new(
                                    &e164,
                                    *extra_device_id,
                                ),
                            )?;
                        }
                    }
                }
                Err(e) => return Err(MessageSenderError::ServiceError(e)),
            }
        }

        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    // Equivalent with `getEncryptedMessages`
    async fn create_encrypted_messages(
        &self,
        recipient: &ServiceAddress,
        unidentified_access: Option<UnidentifiedAccess>,
        content: &[u8],
    ) -> Result<Vec<OutgoingPushMessage>, MessageSenderError> {
        let mut messages = vec![];

        let myself = recipient.matches(&self.cipher.local_address);
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

        for device_id in self
            .cipher
            .store_context
            .get_sub_device_sessions(recipient.identifier())?
        {
            trace!("sending message to device {}", device_id);
            if self.cipher.store_context.contains_session(&Address::new(
                recipient.identifier(),
                device_id,
            ))? {
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
        &self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        device_id: i32,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, MessageSenderError> {
        let recipient_address = Address::new(recipient.identifier(), device_id);
        log::trace!("encrypting message for {:?}", recipient_address);

        if !self
            .cipher
            .store_context
            .contains_session(&recipient_address)?
        {
            info!("establishing new session with {:?}", recipient_address);
            let pre_keys = self
                .service
                .get_pre_keys(&self.cipher.context, recipient, device_id)
                .await?;
            for pre_key_bundle in pre_keys {
                if recipient.matches(&self.cipher.local_address)
                    && self.device_id == pre_key_bundle.device_id()
                {
                    trace!("not establishing a session with myself!");
                    continue;
                }

                let pre_key_address = Address::new(
                    recipient.identifier(),
                    pre_key_bundle.device_id(),
                );
                let session_builder = SessionBuilder::new(
                    &self.cipher.context,
                    &self.cipher.store_context,
                    &pre_key_address,
                );
                session_builder.process_pre_key_bundle(&pre_key_bundle)?;
            }
        }

        let message = self.cipher.encrypt(
            &recipient_address,
            unidentified_access,
            content,
        )?;
        Ok(message)
    }

    fn create_multi_device_sent_transcript_content(
        &self,
        recipient: Option<&ServiceAddress>,
        data_message: Option<crate::proto::DataMessage>,
        timestamp: u64,
    ) -> Result<ContentBody, MessageSenderError> {
        use crate::proto::{sync_message, SyncMessage};
        Ok(ContentBody::SynchronizeMessage(SyncMessage {
            sent: Some(sync_message::Sent {
                destination_e164: recipient.and_then(|r| r.e164.clone()),
                message: data_message,
                timestamp: Some(timestamp),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }
}
