use bytes::Bytes;
use prost::Message;
use uuid::Uuid;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{ProfileKey, ProfileKeyCredentialPresentationV1},
};

use crate::{proto::{
    group_attribute_blob, DecryptedGroup, DecryptedGroupChange, DecryptedMember,
    DecryptedPendingMember, DecryptedRequestingMember, DecryptedTimer,
    Group as EncryptedGroup, GroupAttributeBlob, Member as EncryptedMember,
    GroupChange, group_change::Actions as EncryptedGroupChangeActions,
    member::Role, MemberBanned,
}};

pub(crate) struct GroupOperations {
    group_secret_params: GroupSecretParams,
}

pub struct DecryptedAddMembersAction {
    added: DecryptedMember,
    join_from_invite_link: bool,
}

pub struct MemberWithRole {
    user_id: Uuid,
    role: Role,
}

pub struct MemberWithProfileKey {
    uuid: Uuid,
    profile_key: ProfileKey,
}

pub struct DecryptedMemberPendingProfileKey {
    added_by_user_id: Uuid,
    timestamp: u32,
    member: Member,
}

pub struct Member {
    user_id: Uuid,
    profile_key: ProfileKey,
    role: Role,
}

pub struct DecryptedMemberPendingAdminApproval {

}

#[derive(Default)]
pub struct DecryptedGroupChangeActions {
    version: u32,
    source_uuid: Uuid,
    add_members: Vec<DecryptedAddMembersAction>,
    delete_members: Vec<Uuid>,
    modify_member_roles: Vec<MemberWithRole>,
    modify_member_profile_keys: Vec<MemberWithProfileKey>,
    add_pending_members: Vec<DecryptedMemberPendingProfileKey>,
    delete_pending_member: Vec<Uuid>,
    promote_pending_members: Vec<MemberWithProfileKey>,
    modify_title: Vec<GroupAttributeBlob>,
    modify_disappearing_messages_timer: Vec<GroupAttributeBlob>,
    add_member_pending_admin_approvals: Vec<DecryptedMemberPendingAdminApproval>,
    delete_member_pending_admin_approvals: Vec<Uuid>,
    promote_member_pending_admin_approvals: Vec<MemberWithRole>,
    modify_invite_link_password: Option<String>,
    modify_description: Option<GroupAttributeBlob>,
    modify_announcements_only: bool,
    add_members_banned: Vec<MemberBanned>,
    delete_members_banned: Vec<Uuid>,
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
    fn decrypt_uuid(
        &self,
        uuid: &[u8],
    ) -> Result<[u8; 16], GroupDecryptionError> {
        let bytes = self
            .group_secret_params
            .decrypt_uuid(bincode::deserialize(uuid)?)?;
        Ok(bytes)
    }

    fn decrypt_profile_key(
        &self,
        profile_key: &[u8],
        decrypted_uuid: [u8; 16],
    ) -> Result<ProfileKey, GroupDecryptionError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            bincode::deserialize(profile_key)?,
            decrypted_uuid,
        )?)
    }

    fn decrypt_member(
        &self,
        member: EncryptedMember,
    ) -> Result<DecryptedMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, uuid)?;
            (uuid, profile_key)
        } else {
            let profile_key_credential_presentation: ProfileKeyCredentialPresentationV1 = bincode::deserialize(&member.presentation)?;
            let uuid = self.group_secret_params.decrypt_uuid(
                profile_key_credential_presentation.get_uuid_ciphertext(),
            )?;
            let profile_key = self.group_secret_params.decrypt_profile_key(
                profile_key_credential_presentation
                    .get_profile_key_ciphertext(),
                uuid,
            )?;
            (uuid, profile_key)
        };
        Ok(DecryptedMember {
            uuid: uuid.to_vec(),
            profile_key: bincode::serialize(&profile_key)?,
            role: member.role,
            joined_at_revision: member.joined_at_revision,
        })
    }

    fn decrypt_group_change(
        &self,
        group_change: GroupChange,
    ) -> Result<DecryptedGroupChange, GroupDecryptionError> {
        let actions: EncryptedGroupChangeActions = Message::decode(group_change.actions.into())?;

        let uuid = self.decrypt_uuid(&actions.source_uuid)?;

        let add_members: Vec<DecryptedMember> = actions.add_members.into_iter().filter_map(|add_member| {
            self.decrypt_member(add_member.added?).ok()
        }).collect();

        let delete_members: Vec<[u8; 16]> = actions.delete_members.into_iter().filter_map(|delete_member| {
            self.decrypt_uuid(&delete_member.deleted_user_id).ok()
        }).collect();

        let modify_member_roles: Vec<DecryptedMemberRole> = actions.modify_member_roles.into_iter().filter_map(|modify_member| {
            self.decrypt_uuid(&modify_member.user_id).ok()
        }).collect();

        // "Unknown" UUID with zeroes in case of errors, see: UuidUtil.java:16
        // let added_by = self.decrypt_uuid(&member.added_by_user_id)?;

        Ok(DecryptedPendingMember {
            uuid: uuid.to_vec(),
            role: inner_member.role,
            added_by_uuid: added_by.to_vec(),
            timestamp: member.timestamp,
            uuid_cipher_text: inner_member.user_id,
        })
    }

    fn decrypt_requesting_member(
        &self,
        member: EncryptedRequestingMember,
    ) -> Result<DecryptedRequestingMember, GroupDecryptionError> {
        let (uuid, profile_key) = if member.presentation.is_empty() {
            let uuid = self.decrypt_uuid(&member.user_id)?;
            let profile_key =
                self.decrypt_profile_key(&member.profile_key, uuid)?;
            (uuid, profile_key)
        } else {
            let profile_key_credential_presentation: ProfileKeyCredentialPresentationV1 = bincode::deserialize(&member.presentation)?;
            let uuid = self.group_secret_params.decrypt_uuid(
                profile_key_credential_presentation.get_uuid_ciphertext(),
            )?;
            let profile_key = self.group_secret_params.decrypt_profile_key(
                profile_key_credential_presentation
                    .get_profile_key_ciphertext(),
                uuid,
            )?;
            (uuid, profile_key)
        };
        Ok(DecryptedRequestingMember {
            profile_key: bincode::serialize(&profile_key)?,
            uuid: uuid.to_vec(),
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
            _ => "".into(), // TODO: return an error here?
        }
    }

    fn decrypt_description(&self, ciphertext: &[u8]) -> String {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::Description(title)) => title,
            _ => "".into(), // TODO: return an error here?
        }
    }

    fn decrypt_disappearing_message_timer(
        &self,
        ciphertext: &[u8],
    ) -> Option<DecryptedTimer> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::DisappearingMessagesDuration(duration)) => {
                Some(DecryptedTimer { duration })
            },
            _ => None,
        }
    }

    pub fn decrypt_group(
        group_secret_params: GroupSecretParams,
        group: EncryptedGroup,
    ) -> Result<DecryptedGroup, GroupDecryptionError> {
        let group_operations = Self {
            group_secret_params,
        };
        let title = group_operations.decrypt_title(&group.title);
        let description =
            group_operations.decrypt_description(&group.description);
        let disappearing_messages_timer = group_operations
            .decrypt_disappearing_message_timer(
                &group.disappearing_messages_timer,
            );
        let members = group
            .members
            .into_iter()
            .map(|m| group_operations.decrypt_member(m))
            .collect::<Result<_, _>>()?;
        let pending_members = group
            .pending_members
            .into_iter()
            .map(|m| group_operations.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;
        let requesting_members = group
            .requesting_members
            .into_iter()
            .map(|m| group_operations.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;
        Ok(DecryptedGroup {
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
}
