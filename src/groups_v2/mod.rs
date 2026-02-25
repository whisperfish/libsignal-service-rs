//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
pub mod credentials;
mod endorsements;
mod manager;
mod model;
mod operations;
pub mod utils;

pub use credentials::{
    CredentialError, CredentialReceived, GroupOperationManager, Idle,
    RequestCreated,
};
pub use endorsements::{
    decode_group_send_endorsements_response, GroupSendCombinedEndorsement,
    GroupSendEndorsementError, GroupSendEndorsementsData,
    GroupSendMemberEndorsement, GroupSendToken, GroupSendTokenBuilder,
};
pub use manager::{
    CredentialsCache, CredentialsCacheError, GroupCreationOptions, GroupsManager,
    InMemoryCredentialsCache, decrypt_group,
};
pub use model::{
    AccessControl, AccessRequired, Group, GroupCandidate, GroupChange,
    GroupChanges, Member, PendingMember, RequestingMember, Role, Timer,
};
pub use operations::{GroupDecodingError, GroupOperations};
