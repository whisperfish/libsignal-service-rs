mod account_manager;
pub mod configuration;
pub mod envelope;
pub mod models;
pub mod push_service;
pub mod receiver;

mod proto;

pub use crate::account_manager::AccountManager;

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub struct TrustStore;
