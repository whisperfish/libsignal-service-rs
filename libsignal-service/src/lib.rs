mod account_manager;
pub mod configuration;
pub mod push_service;
pub mod receiver;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub struct TrustStore;
