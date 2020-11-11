use libsignal_protocol::{Address, SessionBuilder};
use log::{info, trace};

use crate::{
    cipher::ServiceCipher, content::ContentBody, push_service::*,
    ServiceAddress,
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

/// Equivalent of Java's `SignalServiceMessageSender`.
#[derive(Clone)]
pub struct MessageSender<Service> {
    service: Service,
    cipher: ServiceCipher,
    device_id: i32,
}

#[derive(thiserror::Error, Debug)]
pub enum MessageSenderError {
    #[error("{0}")]
    ServiceError(#[from] ServiceError),
    #[error("protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),

    #[error("Untrusted identity key!")]
    UntrustedIdentityException,

    #[error("No pre-key found to establish session with {0:?}")]
    NoPreKey(ServiceAddress),

    #[error("Please try again")]
    TryAgain,

    #[error("Exceeded maximum number of retries")]
    MaximumRetriesLimitExceeded,
}

impl<Service> MessageSender<Service>
where
    Service: PushService,
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

    /// Send a message `content` to a single `recipient`.
    pub async fn send_message(
        &mut self,
        recipient: impl std::borrow::Borrow<ServiceAddress>,
        content: impl Into<crate::content::ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Result<SendMessageResponse, MessageSenderError> {
        let content_body = content.into();
        let recipient = recipient.borrow();

        use crate::proto::data_message::Flags;
        let end_session = match &content_body {
            ContentBody::DataMessage(message) => {
                message.flags == Some(Flags::EndSession as u32)
            }
            _ => false,
        };

        let content = content_body.clone().into_proto();
        let response = self
            .try_send_message(recipient, &content, timestamp, online)
            .await?;

        if response.needs_sync {
            let content = self.create_multi_device_sent_transcript_content(
                Some(recipient),
                &content,
                timestamp,
            )?;
            self.try_send_message(
                &self.cipher.local_address.clone(),
                &content,
                timestamp,
                false,
            )
            .await?;
        }

        if end_session {
            if let Some(ref uuid) = recipient.uuid {
                self.cipher.store_context.delete_all_sessions(&uuid)?;
            }
            if let Some(ref e164) = recipient.e164 {
                self.cipher.store_context.delete_all_sessions(&e164)?;
            }
        }

        Ok(response)
    }

    /// Send a message (`content`) to an address (`recipient`).
    async fn try_send_message(
        &mut self,
        recipient: &ServiceAddress,
        content: &crate::proto::Content,
        timestamp: u64,
        online: bool,
    ) -> Result<SendMessageResponse, MessageSenderError> {
        use prost::Message;
        let mut content_bytes = Vec::with_capacity(content.encoded_len());
        content
            .encode(&mut content_bytes)
            .expect("infallible message encoding");

        for _ in 0..4 {
            match self
                .send_messages(recipient, &content_bytes, timestamp, online)
                .await
            {
                Err(MessageSenderError::TryAgain) => continue,
                r => return r,
            }
        }
        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    /// Send the same message to all established sessions (sub-devices) of a recipient
    ///
    /// If the server responds with either extra sessions or missing sessions, this function
    /// will establish them and return `MessageSenderError::TryAgain`
    async fn send_messages(
        &mut self,
        recipient: &ServiceAddress,
        content: &[u8],
        timestamp: u64,
        online: bool,
    ) -> Result<SendMessageResponse, MessageSenderError> {
        let messages = self
            .create_encrypted_messages(&recipient, None, &content)
            .await?;

        let messages = OutgoingPushMessages {
            destination: recipient.identifier(),
            timestamp,
            messages,
            online,
        };

        match self.service.send_messages(messages).await {
            Ok(m) => {
                log::debug!("message sent!");
                Ok(m)
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
                        MessageSenderError::UntrustedIdentityException
                    })?;
                }

                Err(MessageSenderError::TryAgain)
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

                Err(MessageSenderError::TryAgain)
            }
            Err(e) => Err(MessageSenderError::ServiceError(e)),
        }
    }

    // Equivalent with `getEncryptedMessages`
    async fn create_encrypted_messages(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<bool>,
        content: &[u8],
    ) -> Result<Vec<OutgoingPushMessage>, MessageSenderError> {
        let mut messages = vec![];

        let myself = recipient.matches(&self.cipher.local_address);
        if !myself || unidentified_access.is_some() {
            trace!("sending message to default device");
            messages.push(
                self.create_encrypted_message(
                    recipient,
                    unidentified_access,
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
                        unidentified_access,
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
        unidentified_access: Option<bool>,
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

    /**

    private byte[] createMultiDeviceSentTranscriptContent(byte[] content, Optional<SignalServiceAddress> recipient,
                                                          long timestamp, List<SendMessageResult> sendMessageResults,
                                                          boolean isRecipientUpdate)
    {
      try {
        Content.Builder          container   = Content.newBuilder();
        SyncMessage.Builder      syncMessage = createSyncMessageBuilder();
        SyncMessage.Sent.Builder sentMessage = SyncMessage.Sent.newBuilder();
        DataMessage              dataMessage = Content.parseFrom(content).getDataMessage();

        sentMessage.setTimestamp(timestamp);
        sentMessage.setMessage(dataMessage);

        for (SendMessageResult result : sendMessageResults) {
          if (result.getSuccess() != null) {
            SyncMessage.Sent.UnidentifiedDeliveryStatus.Builder builder = SyncMessage.Sent.UnidentifiedDeliveryStatus.newBuilder();

            if (result.getAddress().getUuid().isPresent()) {
              builder = builder.setDestinationUuid(result.getAddress().getUuid().get().toString());
            }

            if (result.getAddress().getNumber().isPresent()) {
              builder = builder.setDestinationE164(result.getAddress().getNumber().get());
            }

            builder.setUnidentified(result.getSuccess().isUnidentified());

            sentMessage.addUnidentifiedStatus(builder.build());
          }
        }

        if (recipient.isPresent()) {
          if (recipient.get().getUuid().isPresent())   sentMessage.setDestinationUuid(recipient.get().getUuid().get().toString());
          if (recipient.get().getNumber().isPresent()) sentMessage.setDestinationE164(recipient.get().getNumber().get());
        }

        if (dataMessage.getExpireTimer() > 0) {
          sentMessage.setExpirationStartTimestamp(System.currentTimeMillis());
        }

        if (dataMessage.getIsViewOnce()) {
          dataMessage = dataMessage.toBuilder().clearAttachments().build();
          sentMessage.setMessage(dataMessage);
        }

        sentMessage.setIsRecipientUpdate(isRecipientUpdate);

        return container.setSyncMessage(syncMessage.setSent(sentMessage)).build().toByteArray();
      } catch (InvalidProtocolBufferException e) {
        throw new AssertionError(e);
      }
    }


    private byte[] createMultiDeviceSentTranscriptContent(byte[] content, Optional<SignalServiceAddress> recipient,
                                                          long timestamp, List<SendMessageResult> sendMessageResults,
                                                          boolean isRecipientUpdate)
      **/

    fn create_multi_device_sent_transcript_content(
        &self,
        recipient: Option<&ServiceAddress>,
        content: &crate::proto::Content,
        timestamp: u64,
    ) -> Result<crate::proto::Content, MessageSenderError> {
        use crate::proto::{sync_message, Content, SyncMessage};
        Ok(Content {
            sync_message: Some(SyncMessage {
                sent: Some(sync_message::Sent {
                    destination_e164: recipient.and_then(|r| r.e164.clone()),
                    message: content.data_message.clone(),
                    timestamp: Some(timestamp),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}
