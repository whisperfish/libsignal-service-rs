mod account_manager;
pub mod configuration;
pub mod envelope;
pub mod models;
pub mod push_service;
pub mod receiver;

mod proto;

mod utils;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub struct TrustStore;

pub mod prelude {
    pub use crate::{
        configuration::{Credentials, ServiceConfiguration},
        receiver::MessageReceiver,
    };
}
