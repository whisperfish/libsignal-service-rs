use crate::{configuration::*, envelope::Envelope, push_service::*};

use libsignal_protocol::StoreContext;

/// Equivalent of Java's `SignalServiceMessageReceiver`.
pub struct MessageReceiver<Service> {
    service: Service,
    context: StoreContext,
}

#[derive(thiserror::Error, Debug)]
pub enum MessageReceiverError {
    #[error("ServiceError")]
    ServiceError(#[from] ServiceError),
}

impl<Service: PushService> MessageReceiver<Service> {
    pub fn new(service: Service, context: StoreContext) -> Self {
        MessageReceiver { service, context }
    }

    /// One-off method to receive all pending messages.
    ///
    /// Equivalent with Java's `SignalServiceMessageReceiver::retrieveMessages`.
    ///
    /// For streaming messages, use a `MessagePipe` through
    /// [`MessageReceiver::create_message_pipe()`].
    pub async fn retrieve_messages(
        &mut self,
    ) -> Result<Vec<Envelope>, MessageReceiverError> {
        let _entities = self.service.get_messages().await?;
        Ok(vec![])
    }

    pub async fn create_message_pipe(&self) -> () { unimplemented!() }
}
