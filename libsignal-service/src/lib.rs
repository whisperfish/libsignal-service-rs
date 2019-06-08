mod account_manager;

pub use crate::account_manager::{AccountManager, AccountManagerBuilder};

pub const USER_AGENT: &'static str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub struct TrustStore;
