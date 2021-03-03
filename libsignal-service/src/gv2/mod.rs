//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod api;
mod models;

pub use api::{CredentialsCache, CredentialsCacheError, GroupsV2Api};
pub use zkgroup::auth::AuthCredentialResponse;
