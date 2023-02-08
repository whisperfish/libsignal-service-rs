use core::fmt;

use bytes::Bytes;
use prost::Message;
use uuid::Uuid;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{AnyProfileKeyCredentialPresentation, ProfileKey},
};

use crate::proto::{
    self, access_control::AccessRequired, group_attribute_blob, member::Role,
    AccessControl, GroupAttributeBlob, Member as EncryptedMember,
};

pub(crate) struct GroupOperations {
    pub group_secret_params: GroupSecretParams,
}

#[derive(Clone)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingMember {
    pub uuid: Uuid,
    pub role: Role,
    pub added_by_uuid: Uuid,
    pub timestamp: u64,
}

#[derive(Clone)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Debug, thiserror::Error)]
pub enum GroupDecryptionError {
    #[error("zero-knowledge group deserialization failure")]
    ZkGroupDeserializationFailure,
    #[error("zero-knowledge group verification failure")]
    ZkGroupVerificationFailure,
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error("protobuf message decoding error: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("wrong group attribute blob")]
    WrongBlob,
    #[error("wrong enum value")]
    WrongEnumValue,
}

impl From<zkgroup::ZkGroupDeserializationFailure> for GroupDecryptionError {
    fn from(_: zkgroup::ZkGroupDeserializationFailure) -> Self {
        GroupDecryptionError::ZkGroupDeserializationFailure
    }
}

impl From<zkgroup::ZkGroupVerificationFailure> for GroupDecryptionError {
    fn from(_: zkgroup::ZkGroupVerificationFailure) -> Self {
        GroupDecryptionError::ZkGroupVerificationFailure
    }
}

impl GroupOperations {
    fn decrypt_uuid(&self, uuid: &[u8]) -> Result<Uuid, GroupDecryptionError> {
        let bytes = self
            .group_secret_params
            .decrypt_uuid(bincode::deserialize(uuid)?)?;
        Ok(Uuid::from_bytes(bytes))
    }

    fn decrypt_profile_key(
        &self,
        encrypted_profile_key: &[u8],
        decrypted_uuid: &Uuid,
    ) -> Result<ProfileKey, GroupDecryptionError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            bincode::deserialize(encrypted_profile_key)?,
            *decrypted_uuid.as_bytes(),
        )?)
    }

    fn decrypt_profile_key_presentation(
        &self,
        presentation: &[u8],
    ) -> Result<(Uuid, ProfileKey), GroupDecryptionError> {
        let profile_key_credential_presentation =
            AnyProfileKeyCredentialPresentation::new(presentation)?;
        let uuid = Uuid::from_bytes(self.group_secret_params.decrypt_uuid(
            profile_key_credential_presentation.get_uuid_ciphertext(),
        )?);
        let profile_key = self.group_secret_params.decrypt_profile_key(
            profile_key_credential_presentation.get_profile_key_ciphertext(),
            *uuid.as_bytes(),
        )?;
        Ok((uuid, profile_key))
    }

    fn decrypt_member(
        &self,
        member: EncryptedMember,
    ) -> Result<Member, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, &uuid)?;
            (uuid, profile_key)
        } else {
            self.decrypt_profile_key_presentation(&member.presentation)?
        };
        Ok(Member {
            uuid,
            profile_key,
            role: Role::from_i32(member.role)
                .ok_or(GroupDecryptionError::WrongBlob)?,
            joined_at_revision: member.joined_at_revision,
        })
    }

    fn decrypt_pending_member(
        &self,
        member: proto::PendingMember,
    ) -> Result<PendingMember, GroupDecryptionError> {
        let inner_member =
            member.member.ok_or(GroupDecryptionError::WrongBlob)?;
        // "Unknown" UUID with zeroes in case of errors, see: UuidUtil.java:16
        let uuid = self.decrypt_uuid(&inner_member.user_id).unwrap_or_default();
        let added_by_uuid = self.decrypt_uuid(&member.added_by_user_id)?;

        Ok(PendingMember {
            uuid,
            role: Role::from_i32(inner_member.role)
                .ok_or(GroupDecryptionError::WrongBlob)?,
            added_by_uuid,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_requesting_member(
        &self,
        member: proto::RequestingMember,
    ) -> Result<RequestingMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, &uuid)?;
            (uuid, profile_key)
        } else {
            self.decrypt_profile_key_presentation(&member.presentation)?
        };
        Ok(RequestingMember {
            profile_key,
            uuid,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_blob(&self, bytes: &[u8]) -> GroupAttributeBlob {
        if bytes.is_empty() {
            GroupAttributeBlob::default()
        } else if bytes.len() < 29 {
            log::warn!("bad encrypted blob length");
            GroupAttributeBlob::default()
        } else {
            self.group_secret_params
                .decrypt_blob(bytes)
                .map_err(GroupDecryptionError::from)
                .and_then(|b| {
                    GroupAttributeBlob::decode(Bytes::copy_from_slice(&b[4..]))
                        .map_err(GroupDecryptionError::ProtobufDecodeError)
                })
                .unwrap_or_else(|e| {
                    log::warn!("bad encrypted blob: {}", e);
                    GroupAttributeBlob::default()
                })
        }
    }

    fn decrypt_title(&self, ciphertext: &[u8]) -> String {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Title(title)) => title,
            _ => "".into(),
        }
    }

    fn decrypt_description(&self, ciphertext: &[u8]) -> Option<String> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Description(d)) => Some(d).filter(|d| !d.is_empty()),
            _ => None,
        }
    }

    fn decrypt_disappearing_message_timer(
        &self,
        ciphertext: &[u8],
    ) -> Option<Timer> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::DisappearingMessagesDuration(duration)) => {
                Some(Timer { duration })
            },
            _ => None,
        }
    }

    pub fn new(group_secret_params: GroupSecretParams) -> Self {
        Self {
            group_secret_params,
        }
    }

    pub fn decrypt_group(
        &self,
        group: proto::Group,
    ) -> Result<Group, GroupDecryptionError> {
        let title = self.decrypt_title(&group.title);

        let description = self.decrypt_description(&group.description);

        let disappearing_messages_timer = self
            .decrypt_disappearing_message_timer(
                &group.disappearing_messages_timer,
            );

        let members = group
            .members
            .into_iter()
            .map(|m| self.decrypt_member(m))
            .collect::<Result<_, _>>()?;

        let pending_members = group
            .pending_members
            .into_iter()
            .map(|m| self.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;

        let requesting_members = group
            .requesting_members
            .into_iter()
            .map(|m| self.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        Ok(Group {
            title,
            avatar: group.avatar,
            disappearing_messages_timer,
            access_control: group.access_control,
            revision: group.revision,
            members,
            pending_members,
            requesting_members,
            invite_link_password: group.invite_link_password,
            description,
        })
    }

    pub fn decrypt_group_change(
        &self,
        group_change: proto::GroupChange,
    ) -> Result<GroupChanges, GroupDecryptionError> {
        let actions: proto::group_change::Actions =
            Message::decode(Bytes::from(group_change.actions))?;

        let uuid = self.decrypt_uuid(&actions.source_uuid)?;

        let new_members =
            actions.add_members.into_iter().filter_map(|m| m.added).map(
                |added| Ok(GroupChange::NewMember(self.decrypt_member(added)?)),
            );

        let delete_members = actions.delete_members.into_iter().map(|c| {
            Ok(GroupChange::DeleteMember(
                self.decrypt_uuid(&c.deleted_user_id)?,
            ))
        });

        let modify_member_roles =
            actions.modify_member_roles.into_iter().map(|m| {
                Ok(GroupChange::ModifyMemberRole {
                    uuid: self.decrypt_uuid(&m.user_id)?,
                    role: Role::from_i32(m.role)
                        .ok_or(GroupDecryptionError::WrongEnumValue)?,
                })
            });

        let modify_member_profile_keys =
            actions.modify_member_profile_keys.into_iter().map(|m| {
                let (uuid, profile_key) =
                    self.decrypt_profile_key_presentation(&m.presentation)?;
                Ok(GroupChange::ModifyMemberProfileKey { uuid, profile_key })
            });

        let add_pending_members = actions
            .add_pending_members
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewPendingMember(
                    self.decrypt_pending_member(added)?,
                ))
            });

        let delete_pending_members =
            actions.delete_pending_members.into_iter().map(|m| {
                Ok(GroupChange::DeletePendingMember(
                    self.decrypt_uuid(&m.deleted_user_id)?,
                ))
            });

        let promote_pending_members =
            actions.promote_pending_members.into_iter().map(|m| {
                let (uuid, profile_key) =
                    self.decrypt_profile_key_presentation(&m.presentation)?;
                Ok(GroupChange::PromotePendingMember { uuid, profile_key })
            });

        let modify_title = actions
            .modify_title
            .into_iter()
            .map(|m| Ok(GroupChange::Title(self.decrypt_title(&m.title))));

        let modify_avatar = actions
            .modify_avatar
            .into_iter()
            .map(|m| Ok(GroupChange::Avatar(m.avatar)));

        let modify_description =
            actions.modify_description.into_iter().map(|m| {
                Ok(GroupChange::Description(
                    self.decrypt_description(&m.description),
                ))
            });

        let modify_disappearing_messages_timer = actions
            .modify_disappearing_messages_timer
            .into_iter()
            .map(|m| {
                Ok(GroupChange::Timer(
                    self.decrypt_disappearing_message_timer(&m.timer),
                ))
            });

        let modify_attributes_access =
            actions.modify_attributes_access.into_iter().map(|m| {
                Ok(GroupChange::AttributeAccess(
                    AccessRequired::from_i32(m.attributes_access)
                        .ok_or(GroupDecryptionError::WrongEnumValue)?,
                ))
            });

        let modify_member_access =
            actions.modify_member_access.into_iter().map(|m| {
                Ok(GroupChange::MemberAccess(
                    AccessRequired::from_i32(m.members_access)
                        .ok_or(GroupDecryptionError::WrongEnumValue)?,
                ))
            });

        let modify_add_from_invite_link_access = actions
            .modify_add_from_invite_link_access
            .into_iter()
            .map(|m| {
                Ok(GroupChange::InviteLinkAccess(
                    AccessRequired::from_i32(m.add_from_invite_link_access)
                        .ok_or(GroupDecryptionError::WrongEnumValue)?,
                ))
            });

        let add_requesting_members = actions
            .add_requesting_members
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewRequestingMember(
                    self.decrypt_requesting_member(added)?,
                ))
            });

        let delete_requesting_members =
            actions.delete_requesting_members.into_iter().map(|m| {
                Ok(GroupChange::DeleteRequestingMember(
                    self.decrypt_uuid(&m.deleted_user_id)?,
                ))
            });

        let promote_requesting_members =
            actions.promote_requesting_members.into_iter().map(|m| {
                Ok(GroupChange::PromoteRequestingMember {
                    uuid: self.decrypt_uuid(&m.user_id)?,
                    role: Role::from_i32(m.role)
                        .ok_or(GroupDecryptionError::WrongEnumValue)?,
                })
            });

        let modify_invite_link_password =
            actions.modify_invite_link_password.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkPassword(base64::encode(
                    m.invite_link_password,
                )))
            });

        let modify_announcements_only = actions
            .modify_announcements_only
            .into_iter()
            .map(|m| Ok(GroupChange::AnnouncementOnly(m.announcements_only)));

        let changes: Result<Vec<GroupChange>, GroupDecryptionError> =
            new_members
                .chain(delete_members)
                .chain(modify_member_roles)
                .chain(modify_member_profile_keys)
                .chain(add_pending_members)
                .chain(delete_pending_members)
                .chain(promote_pending_members)
                .chain(modify_title)
                .chain(modify_avatar)
                .chain(modify_disappearing_messages_timer)
                .chain(modify_attributes_access)
                .chain(modify_description)
                .chain(modify_member_access)
                .chain(modify_add_from_invite_link_access)
                .chain(add_requesting_members)
                .chain(delete_requesting_members)
                .chain(promote_requesting_members)
                .chain(modify_invite_link_password)
                .chain(modify_announcements_only)
                .collect();

        Ok(GroupChanges {
            editor: uuid,
            revision: actions.revision,
            changes: changes?,
        })
    }

    pub fn decrypt_avatar(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Avatar(d)) => Some(d).filter(|d| !d.is_empty()),
            _ => None,
        }
    }
}
