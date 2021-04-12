//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod manager;
mod operations;
pub mod utils;

pub use manager::{
    CredentialsCache, CredentialsCacheError, GroupsManager,
    InMemoryCredentialsCache,
};
pub use operations::GroupDecryptionError;
