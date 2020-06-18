use crate::{configuration::*, envelope::Envelope, push_service::PushService};

use libsignal_protocol::StoreContext;

/// Equivalent of Java's `SignalServiceMessageReceiver`.
pub struct MessageReceiver<Service> {
    service: Service,
    context: StoreContext,
}

impl<Service: PushService> MessageReceiver<Service> {
    pub fn new(service: Service, context: StoreContext) -> Self {
        MessageReceiver { service, context }
    }

    /// One-off method to receive all pending messages.
    ///
    /// For streaming messages, use a `MessagePipe` through
    /// [`MessageReceiver::create_message_pipe()`].
    pub async fn receive_messages(&mut self) -> Vec<Envelope> { vec![] }

    pub async fn create_message_pipe(&self) -> () { unimplemented!() }
}
