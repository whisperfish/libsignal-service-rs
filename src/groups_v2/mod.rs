//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
pub mod credentials;
mod manager;
mod model;
mod operations;
pub mod utils;

pub use manager::{
    decrypt_group, CredentialsCache, CredentialsCacheError, GroupsManager,
    InMemoryCredentialsCache,
};
pub use model::{
    AccessControl, AccessRequired, Group, GroupCandidate, GroupChange,
    GroupChanges, Member, PendingMember, RequestingMember, Role, Timer,
};
pub use operations::{GroupDecodingError, GroupOperations};
