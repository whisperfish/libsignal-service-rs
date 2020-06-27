use crate::{envelope::Envelope, messagepipe::MessagePipe, push_service::*};

/// Equivalent of Java's `SignalServiceMessageReceiver`.
pub struct MessageReceiver<Service> {
    service: Service,
}

#[derive(thiserror::Error, Debug)]
pub enum MessageReceiverError {
    #[error("ServiceError")]
    ServiceError(#[from] ServiceError),
}

impl<Service: PushService> MessageReceiver<Service> {
    pub fn new(service: Service) -> Self { MessageReceiver { service } }

    /// One-off method to receive all pending messages.
    ///
    /// Equivalent with Java's `SignalServiceMessageReceiver::retrieveMessages`.
    ///
    /// For streaming messages, use a `MessagePipe` through
    /// [`MessageReceiver::create_message_pipe()`].
    pub async fn retrieve_messages(
        &mut self,
    ) -> Result<Vec<Envelope>, MessageReceiverError> {
        let entities = self.service.get_messages().await?;
        let entities = entities.into_iter().map(Envelope::from).collect();
        Ok(entities)
    }

    pub async fn create_message_pipe(
        &mut self,
    ) -> Result<MessagePipe<Service::WebSocket>, MessageReceiverError> {
        Ok(MessagePipe::from_socket(self.service.ws().await?))
    }
}
