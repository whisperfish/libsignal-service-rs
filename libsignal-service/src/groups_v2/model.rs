use std::{convert::TryFrom, convert::TryInto, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

use super::GroupDecryptionError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Unknown,
    Default,
    Administrator,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Member {
    pub uuid: Uuid,
    pub role: Role,
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Member")
            .field("uuid", &self.uuid)
            .field("role", &self.role)
            .field("joined_at_revision", &self.joined_at_revision)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingMember {
    pub uuid: Uuid,
    pub role: Role,
    pub added_by_uuid: Uuid,
    pub timestamp: u64,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct RequestingMember {
    pub uuid: Uuid,
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl PartialEq for RequestingMember {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl fmt::Debug for RequestingMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestingMember")
            .field("uuid", &self.uuid)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessRequired {
    Unknown,
    Any,
    Member,
    Administrator,
    Unsatisfiable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessControl {
    pub attributes: AccessRequired,
    pub members: AccessRequired,
    pub add_from_invite_link: AccessRequired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub title: String,
    pub avatar: String,
    pub disappearing_messages_timer: Option<Timer>,
    pub access_control: Option<AccessControl>,
    pub revision: u32,
    pub members: Vec<Member>,
    pub pending_members: Vec<PendingMember>,
    pub requesting_members: Vec<RequestingMember>,
    pub invite_link_password: Vec<u8>,
    pub description: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GroupChanges {
    pub editor: Uuid,
    pub revision: u32,
    pub changes: Vec<GroupChange>,
}

#[derive(Clone)]
pub enum GroupChange {
    NewMember(Member),
    DeleteMember(Uuid),
    ModifyMemberRole { uuid: Uuid, role: Role },
    ModifyMemberProfileKey { uuid: Uuid, profile_key: ProfileKey },
    // for open groups
    NewPendingMember(PendingMember),
    DeletePendingMember(Uuid),
    PromotePendingMember { uuid: Uuid, profile_key: ProfileKey },
    // when admin control is enabled
    NewRequestingMember(RequestingMember),
    DeleteRequestingMember(Uuid),
    PromoteRequestingMember { uuid: Uuid, role: Role },
    // group metadata
    Title(String),
    Avatar(String),
    Timer(Option<Timer>),
    Description(Option<String>),
    AttributeAccess(AccessRequired),
    MemberAccess(AccessRequired),
    InviteLinkAccess(AccessRequired),
    InviteLinkPassword(String),
    AnnouncementOnly(bool),
}

impl fmt::Debug for GroupChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewMember(arg0) => {
                f.debug_tuple("NewMember").field(arg0).finish()
            },
            Self::DeleteMember(arg0) => {
                f.debug_tuple("DeleteMember").field(arg0).finish()
            },
            Self::ModifyMemberRole { uuid, role } => f
                .debug_struct("ModifyMemberRole")
                .field("uuid", uuid)
                .field("role", role)
                .finish(),
            Self::ModifyMemberProfileKey { uuid, .. } => f
                .debug_struct("ModifyMemberProfileKey")
                .field("uuid", uuid)
                .finish(),
            Self::NewPendingMember(arg0) => {
                f.debug_tuple("NewPendingMember").field(arg0).finish()
            },
            Self::DeletePendingMember(arg0) => {
                f.debug_tuple("DeletePendingMember").field(arg0).finish()
            },
            Self::PromotePendingMember { uuid, .. } => f
                .debug_struct("PromotePendingMember")
                .field("uuid", uuid)
                .finish(),
            Self::NewRequestingMember(arg0) => {
                f.debug_tuple("NewRequestingMember").field(arg0).finish()
            },
            Self::DeleteRequestingMember(arg0) => {
                f.debug_tuple("DeleteRequestingMember").field(arg0).finish()
            },
            Self::PromoteRequestingMember { uuid, role } => f
                .debug_struct("PromoteRequestingMember")
                .field("uuid", uuid)
                .field("role", role)
                .finish(),
            Self::Title(arg0) => f.debug_tuple("Title").field(arg0).finish(),
            Self::Avatar(arg0) => f.debug_tuple("Avatar").field(arg0).finish(),
            Self::Timer(arg0) => f.debug_tuple("Timer").field(arg0).finish(),
            Self::Description(arg0) => {
                f.debug_tuple("Description").field(arg0).finish()
            },
            Self::AttributeAccess(arg0) => {
                f.debug_tuple("AttributeAccess").field(arg0).finish()
            },
            Self::MemberAccess(arg0) => {
                f.debug_tuple("MemberAccess").field(arg0).finish()
            },
            Self::InviteLinkAccess(arg0) => {
                f.debug_tuple("InviteLinkAccess").field(arg0).finish()
            },
            Self::InviteLinkPassword(arg0) => {
                f.debug_tuple("InviteLinkPassword").field(arg0).finish()
            },
            Self::AnnouncementOnly(arg0) => {
                f.debug_tuple("AnnouncementOnly").field(arg0).finish()
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Timer {
    pub duration: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct GroupJoinInfo {
    pub title: String,
    pub avatar: String,
    pub member_count: u32,
    pub add_from_invite_link: i32,
    pub revision: u32,
    pub pending_admin_approval: bool,
    pub description: String,
}

/// Conversion from protobuf definitions

impl TryFrom<i32> for Role {
    type Error = GroupDecryptionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        use crate::proto::member::Role::*;
        match crate::proto::member::Role::from_i32(value) {
            Some(Unknown) => Ok(Role::Unknown),
            Some(Default) => Ok(Role::Default),
            Some(Administrator) => Ok(Role::Administrator),
            None => Err(GroupDecryptionError::WrongEnumValue),
        }
    }
}

impl TryFrom<i32> for AccessRequired {
    type Error = GroupDecryptionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        use crate::proto::access_control::AccessRequired::*;
        match crate::proto::access_control::AccessRequired::from_i32(value) {
            Some(Unknown) => Ok(AccessRequired::Unknown),
            Some(Any) => Ok(AccessRequired::Any),
            Some(Member) => Ok(AccessRequired::Member),
            Some(Administrator) => Ok(AccessRequired::Administrator),
            Some(Unsatisfiable) => Ok(AccessRequired::Unsatisfiable),
            None => Err(GroupDecryptionError::WrongEnumValue),
        }
    }
}

impl TryFrom<crate::proto::AccessControl> for AccessControl {
    type Error = GroupDecryptionError;

    fn try_from(
        value: crate::proto::AccessControl,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            attributes: value.attributes.try_into()?,
            members: value.members.try_into()?,
            add_from_invite_link: value.add_from_invite_link.try_into()?,
        })
    }
}
