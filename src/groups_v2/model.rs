use std::{convert::TryFrom, convert::TryInto};

use derivative::Derivative;
use libsignal_protocol::ServiceId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

use super::GroupDecodingError;

#[derive(Copy, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Unknown,
    Default,
    Administrator,
}

#[derive(Derivative, Clone, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct Member {
    pub uuid: Uuid,
    pub role: Role,
    #[derivative(Debug = "ignore")]
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMember {
    pub address: ServiceId,
    pub role: Role,
    pub added_by_uuid: Uuid,
    pub timestamp: u64,
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub struct RequestingMember {
    pub uuid: Uuid,
    #[derivative(Debug = "ignore")]
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl PartialEq for RequestingMember {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone)]
pub struct GroupChanges {
    pub editor: Uuid,
    pub revision: u32,
    pub changes: Vec<GroupChange>,
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
pub enum GroupChange {
    NewMember(Member),
    DeleteMember(Uuid),
    ModifyMemberRole {
        uuid: Uuid,
        role: Role,
    },
    ModifyMemberProfileKey {
        uuid: Uuid,
        #[derivative(Debug = "ignore")]
        profile_key: ProfileKey,
    },
    // for open groups
    NewPendingMember(PendingMember),
    DeletePendingMember(Uuid),
    PromotePendingMember {
        uuid: Uuid,
        #[derivative(Debug = "ignore")]
        profile_key: ProfileKey,
    },
    // when admin control is enabled
    NewRequestingMember(RequestingMember),
    DeleteRequestingMember(Uuid),
    PromoteRequestingMember {
        uuid: Uuid,
        role: Role,
    },
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Timer {
    pub duration: u32,
}

// Conversion from and to protobuf definitions

impl TryFrom<i32> for Role {
    type Error = GroupDecodingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        use crate::proto::member::Role::*;
        match crate::proto::member::Role::try_from(value) {
            Ok(Unknown) => Ok(Role::Unknown),
            Ok(Default) => Ok(Role::Default),
            Ok(Administrator) => Ok(Role::Administrator),
            Err(_e) => Err(GroupDecodingError::WrongEnumValue),
        }
    }
}

impl From<Role> for i32 {
    fn from(val: Role) -> Self {
        use crate::proto::member::Role::*;
        match val {
            Role::Unknown => Unknown,
            Role::Default => Default,
            Role::Administrator => Administrator,
        }
        .into()
    }
}

impl TryFrom<i32> for AccessRequired {
    type Error = GroupDecodingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        use crate::proto::access_control::AccessRequired::*;
        match crate::proto::access_control::AccessRequired::try_from(value) {
            Ok(Unknown) => Ok(AccessRequired::Unknown),
            Ok(Any) => Ok(AccessRequired::Any),
            Ok(Member) => Ok(AccessRequired::Member),
            Ok(Administrator) => Ok(AccessRequired::Administrator),
            Ok(Unsatisfiable) => Ok(AccessRequired::Unsatisfiable),
            Err(_e) => Err(GroupDecodingError::WrongEnumValue),
        }
    }
}

impl From<AccessRequired> for i32 {
    fn from(val: AccessRequired) -> Self {
        use crate::proto::access_control::AccessRequired::*;
        match val {
            AccessRequired::Unknown => Unknown,
            AccessRequired::Any => Any,
            AccessRequired::Member => Member,
            AccessRequired::Administrator => Administrator,
            AccessRequired::Unsatisfiable => Unsatisfiable,
        }
        .into()
    }
}

impl TryFrom<crate::proto::AccessControl> for AccessControl {
    type Error = GroupDecodingError;

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
