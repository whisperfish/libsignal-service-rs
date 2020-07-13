mod account_manager;
pub mod configuration;
pub mod envelope;
pub mod messagepipe;
pub mod models;
pub mod push_service;
pub mod receiver;

mod proto;

mod utils;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

/// GROUP_UPDATE_FLAG signals that this message updates the group membership or name.
pub const GROUP_UPDATE_FLAG: u32 = 1;

/// GROUP_LEAVE_FLAG signals that this message is a group leave message.
pub const GROUP_LEAVE_FLAG: u32 = 2;

pub struct TrustStore;

pub struct ServiceAddress {
    pub uuid: Option<String>,
    // In principe, this is also Option<String> if you follow the Java code.
    pub e164: String,
    pub relay: Option<String>,
}

pub mod prelude {
    pub use crate::{
        configuration::{Credentials, ServiceConfiguration},
        envelope::Envelope,
        push_service::ServiceError,
        receiver::MessageReceiver,
    };
}
