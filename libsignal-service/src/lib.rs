#![recursion_limit = "256"]

mod account_manager;
pub mod attachment_cipher;
pub mod cipher;
pub mod configuration;
pub mod content;
pub mod envelope;
pub mod messagepipe;
pub mod models;
pub mod pre_keys;
mod proto;
pub mod provisioning;
pub mod push_service;
pub mod receiver;
pub mod sealed_session_cipher;
pub mod sender;
pub mod utils;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

/// GROUP_UPDATE_FLAG signals that this message updates the group membership or
/// name.
pub const GROUP_UPDATE_FLAG: u32 = 1;

/// GROUP_LEAVE_FLAG signals that this message is a group leave message.
pub const GROUP_LEAVE_FLAG: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAddress {
    pub uuid: Option<String>,
    pub e164: Option<String>,
    pub relay: Option<String>,
}

impl std::fmt::Display for ServiceAddress {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        match (&self.uuid, &self.e164, &self.relay) {
            (_, Some(e164), _) => write!(f, "ServiceAddress({})", e164),
            (Some(uuid), _, _) => write!(f, "ServiceAddress({})", uuid),
            _ => write!(f, "ServiceAddress(INVALID)"),
        }
    }
}

impl ServiceAddress {
    /// Returns uuid if present, e164 otherwise.
    pub fn identifier(&self) -> &str {
        if let Some(ref uuid) = self.uuid {
            return uuid;
        } else if let Some(ref e164) = self.e164 {
            return e164;
        }
        unreachable!(
            "an address requires either a UUID or a E164 phone number"
        );
    }

    pub fn matches(&self, other: &Self) -> bool {
        (self.e164.is_some() && self.e164 == other.e164)
            || (self.uuid.is_some() && self.uuid == other.uuid)
    }
}

pub mod prelude {
    pub use super::ServiceAddress;
    pub use crate::{
        cipher::ServiceCipher,
        configuration::{Credentials, ServiceConfiguration, SignalingKey},
        content::Content,
        envelope::Envelope,
        push_service::{PushService, ServiceError},
        receiver::MessageReceiver,
        sender::{MessageSender, MessageSenderError},
    };
}
