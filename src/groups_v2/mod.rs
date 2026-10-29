//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod invite_link;
mod manager;
mod model;
mod operations;
pub mod utils;

pub use invite_link::GroupInviteLink;
pub use manager::{
    decrypt_group, CredentialsCache, CredentialsCacheError, GroupLogEntry,
    GroupsManager, InMemoryCredentialsCache,
};
pub use model::{
    AccessControl, AccessRequired, Group, GroupChange, GroupChanges,
    GroupJoinInfo, GroupMemberCandidate, Member, PendingMember,
    RequestingMember, Role, Timer,
};
pub use operations::{GroupDecodingError, GroupOperations};
