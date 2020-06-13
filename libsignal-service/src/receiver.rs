use crate::{configuration::*, push_service::PushService};

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
}
