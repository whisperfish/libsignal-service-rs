use crate::{
    cipher::ServiceCipher, configuration::Credentials, envelope::Envelope,
    messagepipe::MessagePipe, push_service::*,
};

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPushMessage {
    pub r#type: u32,
    pub destination_device_id: u32,
    pub destination_registration_id: u32,
    pub content: Vec<u8>,
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
pub struct MessageSender<Service> {
    service: Service,
    cipher: ServiceCipher,
}

#[derive(thiserror::Error, Debug)]
pub enum MessageSenderError {
    #[error("ServiceError")]
    ServiceError(#[from] ServiceError),
}

impl<Service: PushService> MessageSender<Service> {
    pub fn new(service: Service, cipher: ServiceCipher) -> Self {
        MessageSender { service, cipher }
    }

    /// Send a message (`content`) to an address (`recipient`).
    // XXX: `online` supposedly has to do with Typing indicators.
    // Cfr. libsignal-service-java 7eb925190d78360a1aaae13402b6eb747997aeca
    pub async fn send_message(
        &mut self,
        recipient: crate::ServiceAddress,
        content: impl Into<crate::content::ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Result<(), MessageSenderError> {
        let content = {
            use prost::Message;
            let content_proto = content.into().into_proto();
            let mut content = vec![0u8; content_proto.encoded_len()];
            content_proto
                .encode(&mut content)
                .expect("infallible message encoding");
            content
        };

        // Java retries 4 times
        for _ in 0u8..4 {
            // XXX: why is this in the loop? Copied from Java
            let messages =
                self.create_encrypted_messages(&recipient, &content)?;
            let messages = OutgoingPushMessages {
                destination: recipient.get_identifier(),
                timestamp,
                messages,
                online,
            };
            self.service.send_messages(messages).await?;
        }

        Ok(())
    }

    // Equivalent with `getEncryptedMessages`
    fn create_encrypted_messages(
        &mut self,
        recipient: &crate::ServiceAddress,
        content: &[u8],
    ) -> Result<Vec<OutgoingPushMessage>, MessageSenderError> {
        unimplemented!()
    }
}
