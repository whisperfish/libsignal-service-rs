use std::{convert::TryFrom, convert::TryInto};

use libsignal_protocol::{Aci, Pni, ServiceId};
use serde::{Deserialize, Serialize};
use zkgroup::profiles::ProfileKey;

use crate::sender::GroupV2Id;

use super::GroupDecodingError;

#[derive(Copy, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Unknown,
    Default,
    Administrator,
}

#[derive(derive_more::Debug, Clone, Deserialize, Serialize)]
pub struct Member {
    #[serde(with = "aci_serde")]
    pub aci: Aci,
    pub role: Role,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
}

impl PartialEq for Member {
    fn eq(&self, other: &Self) -> bool {
        self.aci == other.aci
    }
}

mod aci_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(p: &Aci, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&p.service_id_string())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Aci, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We have to go through String deserialization,
        // because Aci does not implement Deserialize (duh).
        let s = std::borrow::Cow::<str>::deserialize(d)?;
        match Aci::parse_from_service_id_string(&s) {
            Some(aci) => Ok(aci),
            None => Err(serde::de::Error::custom("Invalid ACI string")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMember {
    pub address: ServiceId,
    pub role: Role,
    pub added_by_aci: Aci,
    pub timestamp: u64,
}

#[derive(derive_more::Debug, Clone)]
pub struct RequestingMember {
    pub aci: Aci,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl PartialEq for RequestingMember {
    fn eq(&self, other: &Self) -> bool {
        self.aci == other.aci
    }
}

#[derive(Debug, Clone)]
pub struct BannedMember {
    pub service_id: ServiceId,
    pub timestamp: u64,
}

impl PartialEq for BannedMember {
    fn eq(&self, other: &Self) -> bool {
        self.service_id == other.service_id
    }
}

#[derive(derive_more::Debug, Clone)]
pub struct PromotedMember {
    pub aci: Aci,
    pub pni: Pni,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
}

impl PartialEq for PromotedMember {
    fn eq(&self, other: &Self) -> bool {
        self.aci == other.aci && self.pni == other.pni
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
    pub announcements_only: bool,
    pub banned_members: Vec<BannedMember>,
}

#[derive(Debug, Clone)]
pub struct GroupChanges {
    pub group_id: GroupV2Id,
    pub editor: Aci,
    pub revision: u32,
    pub changes: Vec<GroupChange>,
    pub change_epoch: u32,
}

#[derive(derive_more::Debug, Clone)]
pub enum GroupChange {
    NewMember(Member),
    DeleteMember(Aci),
    ModifyMemberRole {
        aci: Aci,
        role: Role,
    },
    ModifyMemberProfileKey {
        aci: Aci,
        #[debug(ignore)]
        profile_key: ProfileKey,
    },
    NewPendingMember(PendingMember),
    DeletePendingMember(ServiceId),
    PromotePendingMember {
        address: ServiceId,
        #[debug(ignore)]
        profile_key: ProfileKey,
    },
    Title(String),
    Avatar(String),
    Timer(Option<Timer>),
    AttributeAccess(AccessRequired),
    MemberAccess(AccessRequired),
    InviteLinkAccess(AccessRequired),
    NewRequestingMember(RequestingMember),
    DeleteRequestingMember(Aci),
    PromoteRequestingMember {
        aci: Aci,
        role: Role,
    },
    InviteLinkPassword(String),
    Description(Option<String>),
    AnnouncementOnly(bool),
    AddBannedMember(BannedMember),
    DeleteBannedMember(ServiceId),
    PromotePendingPniAciMemberProfileKey(PromotedMember),
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
