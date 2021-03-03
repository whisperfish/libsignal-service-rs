//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod api;
mod models;
mod operations;

pub use api::{
    CredentialsCache, CredentialsCacheError, GroupsV2Api,
    InMemoryCredentialsCache,
};
pub use operations::GroupDecryptionError;
pub use zkgroup::auth::AuthCredentialResponse;
