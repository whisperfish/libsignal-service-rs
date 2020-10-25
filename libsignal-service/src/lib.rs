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
pub mod sender;
pub mod utils;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

/// GROUP_UPDATE_FLAG signals that this message updates the group membership or
/// name.
pub const GROUP_UPDATE_FLAG: u32 = 1;

/// GROUP_LEAVE_FLAG signals that this message is a group leave message.
pub const GROUP_LEAVE_FLAG: u32 = 2;

pub struct TrustStore;

#[derive(Clone, Debug)]
pub struct ServiceAddress {
    pub uuid: Option<String>,
    // In principe, this is also Option<String> if you follow the Java code.
    pub e164: String,
    pub relay: Option<String>,
}

impl ServiceAddress {
    /// Returns uuid if present, e164 otherwise.
    pub fn get_identifier(&self) -> &str {
        if let Some(uuid) = self.uuid.as_deref() {
            return uuid;
        }
        &self.e164
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
        sender::MessageSender,
    };
}
