use std::convert::TryInto;

use base64::prelude::*;
use bytes::Bytes;
use libsignal_protocol::{Aci, Pni, ServiceId};
use prost::Message;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{AnyProfileKeyCredentialPresentation, ProfileKey},
};

use crate::{
    groups_v2::model::Timer,
    proto::{
        self, group_attribute_blob, GroupAttributeBlob,
        Member as EncryptedMember,
    },
    utils::BASE64_RELAXED,
};

use super::{
    model::{
        BannedMember, Member, PendingMember, PromotedMember, RequestingMember,
    },
    Group, GroupChange, GroupChanges,
};

pub(crate) struct GroupOperations {
    pub group_secret_params: GroupSecretParams,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupDecodingError {
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
    #[error("wrong service ID type: should be ACI")]
    NotAci,
    #[error("wrong service ID type: should be PNI")]
    NotPni,
}

impl From<zkgroup::ZkGroupDeserializationFailure> for GroupDecodingError {
    fn from(_: zkgroup::ZkGroupDeserializationFailure) -> Self {
        GroupDecodingError::ZkGroupDeserializationFailure
    }
}

impl From<zkgroup::ZkGroupVerificationFailure> for GroupDecodingError {
    fn from(_: zkgroup::ZkGroupVerificationFailure) -> Self {
        GroupDecodingError::ZkGroupVerificationFailure
    }
}

impl GroupOperations {
    fn decrypt_service_id(
        &self,
        ciphertext: &[u8],
    ) -> Result<ServiceId, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(bincode::deserialize(ciphertext)?)?
        {
            ServiceId::Aci(aci) => Ok(ServiceId::from(aci)),
            ServiceId::Pni(pni) => Ok(ServiceId::from(pni)),
        }
    }

    fn decrypt_aci(
        &self,
        ciphertext: &[u8],
    ) -> Result<Aci, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(bincode::deserialize(ciphertext)?)?
        {
            ServiceId::Aci(aci) => Ok(aci),
            ServiceId::Pni(pni) => {
                tracing::error!(
                    "Expected Aci, got Pni: {}",
                    pni.service_id_string()
                );
                Err(GroupDecodingError::NotAci)
            },
        }
    }

    fn decrypt_pni(
        &self,
        ciphertext: &[u8],
    ) -> Result<Pni, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(bincode::deserialize(ciphertext)?)?
        {
            ServiceId::Pni(pni) => Ok(pni),
            ServiceId::Aci(aci) => {
                tracing::error!(
                    "Expected Pni, got Aci: {}",
                    aci.service_id_string()
                );
                Err(GroupDecodingError::NotPni)
            },
        }
    }

    fn decrypt_profile_key(
        &self,
        encrypted_profile_key: &[u8],
        decrypted_aci: libsignal_protocol::Aci,
    ) -> Result<ProfileKey, GroupDecodingError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            bincode::deserialize(encrypted_profile_key)?,
            decrypted_aci,
        )?)
    }

    fn decrypt_profile_key_presentation(
        &self,
        aci: &[u8],
        profile_key: &[u8],
        presentation: &[u8],
    ) -> Result<(Aci, ProfileKey), GroupDecodingError> {
        if presentation.is_empty() {
            let aci = self.decrypt_aci(aci)?;
            let profile_key = self.decrypt_profile_key(profile_key, aci)?;
            return Ok((aci, profile_key));
        }

        let profile_key_credential_presentation =
            AnyProfileKeyCredentialPresentation::new(presentation)?;

        match self.group_secret_params.decrypt_service_id(
            profile_key_credential_presentation.get_uuid_ciphertext(),
        )? {
            ServiceId::Aci(aci) => {
                let profile_key =
                    self.group_secret_params.decrypt_profile_key(
                        profile_key_credential_presentation
                            .get_profile_key_ciphertext(),
                        aci,
                    )?;
                Ok((aci, profile_key))
            },
            _ => Err(GroupDecodingError::NotAci),
        }
    }

    fn decrypt_pni_aci_promotion_presentation(
        &self,
        member: &proto::group_change::actions::PromoteMemberPendingPniAciProfileKeyAction,
    ) -> Result<PromotedMember, GroupDecodingError> {
        let aci = self.decrypt_aci(&member.user_id)?;
        let pni = self.decrypt_pni(&member.pni)?;
        let profile_key = self.decrypt_profile_key(&member.profile_key, aci)?;
        Ok(PromotedMember {
            aci,
            pni,
            profile_key,
        })
    }

    fn decrypt_member(
        &self,
        member: EncryptedMember,
    ) -> Result<Member, GroupDecodingError> {
        let (aci, profile_key) = self.decrypt_profile_key_presentation(
            &member.user_id,
            &member.profile_key,
            &member.presentation,
        )?;
        Ok(Member {
            aci,
            profile_key,
            role: member.role.try_into()?,
            joined_at_version: member.joined_at_version,
        })
    }

    fn decrypt_pending_member(
        &self,
        member: proto::MemberPendingProfileKey,
    ) -> Result<PendingMember, GroupDecodingError> {
        let inner_member =
            member.member.ok_or(GroupDecodingError::WrongBlob)?;
        let service_id = self.decrypt_service_id(&inner_member.user_id)?;
        let added_by_aci = self.decrypt_aci(&member.added_by_user_id)?;

        Ok(PendingMember {
            address: service_id,
            role: inner_member.role.try_into()?,
            added_by_aci,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_requesting_member(
        &self,
        member: proto::MemberPendingAdminApproval,
    ) -> Result<RequestingMember, GroupDecodingError> {
        let (aci, profile_key) = self.decrypt_profile_key_presentation(
            &member.user_id,
            &member.profile_key,
            &member.presentation,
        )?;
        Ok(RequestingMember {
            profile_key,
            aci,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_banned_member(
        &self,
        member: proto::MemberBanned,
    ) -> Result<BannedMember, GroupDecodingError> {
        Ok(BannedMember {
            user_id: self.decrypt_service_id(&member.user_id)?,
            timestamp: member.timestamp,
        })
    }

    fn decrypt_string(
        &self,
        bytes: &[u8],
    ) -> Result<String, GroupDecodingError> {
        let bytes = self.group_secret_params.decrypt_blob(bytes)?;
        String::from_utf8(bytes).map_err(|_| GroupDecodingError::WrongBlob)
    }

    fn decrypt_blob(&self, bytes: &[u8]) -> GroupAttributeBlob {
        if bytes.is_empty() {
            GroupAttributeBlob::default()
        } else if bytes.len() < 29 {
            tracing::warn!("bad encrypted blob length");
            GroupAttributeBlob::default()
        } else {
            self.group_secret_params
                .decrypt_blob(bytes)
                .map_err(GroupDecodingError::from)
                .and_then(|b| {
                    GroupAttributeBlob::decode(Bytes::copy_from_slice(&b[4..]))
                        .map_err(GroupDecodingError::ProtobufDecodeError)
                })
                .unwrap_or_else(|e| {
                    tracing::warn!("bad encrypted blob: {}", e);
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

    fn decrypt_description_text(&self, ciphertext: &[u8]) -> Option<String> {
        use group_attribute_blob::Content;
        match self.decrypt_blob(ciphertext).content {
            Some(Content::DescriptionText(d)) => {
                Some(d).filter(|d| !d.is_empty())
            },
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
    ) -> Result<Group, GroupDecodingError> {
        // Destructuring to catch any future changes
        let proto::Group {
            public_key: _,
            title,
            avatar_url,
            disappearing_messages_timer,
            access_control,
            version,
            members,
            members_pending_profile_key,
            members_pending_admin_approval,
            invite_link_password,
            description,
            announcements_only,
            members_banned,
        } = group;

        let title = self.decrypt_title(&title);

        let description_text = self.decrypt_description_text(&description);

        let disappearing_messages_timer = self
            .decrypt_disappearing_message_timer(&disappearing_messages_timer);

        let members = members
            .into_iter()
            .map(|m| self.decrypt_member(m))
            .collect::<Result<_, _>>()?;

        let members_pending_profile_key = members_pending_profile_key
            .into_iter()
            .map(|m| self.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;

        let members_pending_admin_approval = members_pending_admin_approval
            .into_iter()
            .map(|m| self.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        let members_banned = members_banned
            .into_iter()
            .map(|m| self.decrypt_banned_member(m))
            .collect::<Result<_, _>>()?;

        let access_control =
            access_control.map(TryInto::try_into).transpose()?;

        Ok(Group {
            title,
            avatar: avatar_url,
            disappearing_messages_timer,
            access_control,
            version,
            members,
            members_pending_profile_key,
            members_pending_admin_approval,
            invite_link_password,
            description_text,
            announcements_only,
            members_banned,
        })
    }

    pub fn decrypt_group_change(
        &self,
        group_change: proto::GroupChange,
    ) -> Result<GroupChanges, GroupDecodingError> {
        // Destructuring to catch any future changes
        let proto::GroupChange {
            actions,
            server_signature: _,
            change_epoch,
        } = group_change;

        let proto::group_change::Actions {
            group_id,
            source_user_id,
            version,
            add_members,
            delete_members,
            modify_member_roles,
            modify_member_profile_keys,
            add_members_pending_profile_key,
            delete_members_pending_profile_key,
            promote_members_pending_profile_key,
            modify_title,
            modify_avatar,
            modify_disappearing_message_timer,
            modify_attributes_access,
            modify_member_access,
            modify_add_from_invite_link_access,
            add_members_pending_admin_approval,
            delete_members_pending_admin_approval,
            promote_members_pending_admin_approval,
            modify_invite_link_password,
            modify_description,
            modify_announcements_only,
            add_members_banned,
            delete_members_banned,
            promote_members_pending_pni_aci_profile_key,
            modify_member_labels,
            modify_member_label_access,
        } = Message::decode(Bytes::from(actions))?;

        let source_user_id = self.decrypt_aci(&source_user_id)?;

        let new_members =
            add_members
                .into_iter()
                .filter_map(|m| m.added)
                .map(|added| {
                    Ok(GroupChange::NewMember(self.decrypt_member(added)?))
                });

        let delete_members = delete_members.into_iter().map(|c| {
            Ok(GroupChange::DeleteMember(
                self.decrypt_aci(&c.deleted_user_id)?,
            ))
        });

        let modify_member_roles = modify_member_roles.into_iter().map(|m| {
            Ok(GroupChange::ModifyMemberRole {
                aci: self.decrypt_aci(&m.user_id)?,
                role: m.role.try_into()?,
            })
        });

        let modify_member_profile_keys =
            modify_member_profile_keys.into_iter().map(|m| {
                let (aci, profile_key) = self
                    .decrypt_profile_key_presentation(
                        &m.user_id,
                        &m.profile_key,
                        &m.presentation,
                    )?;
                Ok(GroupChange::ModifyMemberProfileKey { aci, profile_key })
            });

        let add_members_pending_profile_key = add_members_pending_profile_key
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewPendingMember(
                    self.decrypt_pending_member(added)?,
                ))
            });

        let delete_members_pending_profile_key =
            delete_members_pending_profile_key.into_iter().map(|m| {
                Ok(GroupChange::DeletePendingMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_profile_key =
            promote_members_pending_profile_key.into_iter().map(|m| {
                let (aci, profile_key) = self
                    .decrypt_profile_key_presentation(
                        &m.user_id,
                        &m.profile_key,
                        &m.presentation,
                    )?;
                Ok(GroupChange::PromotePendingMember {
                    address: aci.into(),
                    profile_key,
                })
            });

        let modify_title = modify_title
            .into_iter()
            .map(|m| Ok(GroupChange::Title(self.decrypt_title(&m.title))));

        let modify_avatar = modify_avatar
            .into_iter()
            .map(|m| Ok(GroupChange::Avatar(m.avatar)));

        let modify_description = modify_description.into_iter().map(|m| {
            Ok(GroupChange::Description(
                self.decrypt_description_text(&m.description),
            ))
        });

        let modify_disappearing_message_timer =
            modify_disappearing_message_timer.into_iter().map(|m| {
                Ok(GroupChange::Timer(
                    self.decrypt_disappearing_message_timer(&m.timer),
                ))
            });

        let modify_attributes_access =
            modify_attributes_access.into_iter().map(|m| {
                Ok(GroupChange::AttributeAccess(
                    m.attributes_access.try_into()?,
                ))
            });

        let modify_member_access = modify_member_access.into_iter().map(|m| {
            Ok(GroupChange::MemberAccess(m.members_access.try_into()?))
        });

        let add_members_banned = add_members_banned
            .into_iter()
            .filter_map(|m| m.added)
            .map(|m| {
                Ok(GroupChange::AddBannedMember(self.decrypt_banned_member(m)?))
            });

        let delete_members_banned =
            delete_members_banned.into_iter().map(|m| {
                Ok(GroupChange::DeleteBannedMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_pni_aci_profile_key =
            promote_members_pending_pni_aci_profile_key
                .into_iter()
                .map(|m| {
                    let promoted =
                        self.decrypt_pni_aci_promotion_presentation(&m)?;
                    Ok(GroupChange::PromotePendingPniAciMemberProfileKey(
                        promoted,
                    ))
                });

        let modify_add_from_invite_link_access =
            modify_add_from_invite_link_access.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkAccess(
                    m.add_from_invite_link_access.try_into()?,
                ))
            });

        let add_members_pending_admin_approval =
            add_members_pending_admin_approval
                .into_iter()
                .filter_map(|m| m.added)
                .map(|added| {
                    Ok(GroupChange::NewRequestingMember(
                        self.decrypt_requesting_member(added)?,
                    ))
                });

        let delete_members_pending_admin_approval =
            delete_members_pending_admin_approval.into_iter().map(|m| {
                Ok(GroupChange::DeleteRequestingMember(
                    self.decrypt_aci(&m.deleted_user_id)?,
                ))
            });

        let promote_members_pending_admin_approval =
            promote_members_pending_admin_approval.into_iter().map(|m| {
                Ok(GroupChange::PromoteRequestingMember {
                    aci: self.decrypt_aci(&m.user_id)?,
                    role: m.role.try_into()?,
                })
            });

        let modify_invite_link_password =
            modify_invite_link_password.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkPassword(
                    BASE64_RELAXED.encode(m.invite_link_password),
                ))
            });

        let modify_announcements_only = modify_announcements_only
            .into_iter()
            .map(|m| Ok(GroupChange::AnnouncementOnly(m.announcements_only)));

        let modify_member_labels = modify_member_labels.into_iter().map(|m| {
            Ok(GroupChange::MemberLabel {
                user_id: self.decrypt_service_id(&m.user_id)?,
                label_emoji: self.decrypt_string(&m.label_emoji)?,
                label_string: self.decrypt_string(&m.label_string)?,
            })
        });

        let modify_member_label_access =
            modify_member_label_access.into_iter().map(|m| {
                Ok(GroupChange::MemberLabelAccess(
                    m.member_label_access.try_into()?,
                ))
            });

        let changes: Result<Vec<GroupChange>, GroupDecodingError> = new_members
            .chain(delete_members)
            .chain(modify_member_roles)
            .chain(modify_member_profile_keys)
            .chain(add_members_pending_profile_key)
            .chain(delete_members_pending_profile_key)
            .chain(promote_members_pending_profile_key)
            .chain(modify_title)
            .chain(modify_avatar)
            .chain(modify_disappearing_message_timer)
            .chain(modify_attributes_access)
            .chain(modify_description)
            .chain(modify_member_access)
            .chain(add_members_banned)
            .chain(delete_members_banned)
            .chain(promote_members_pending_pni_aci_profile_key)
            .chain(modify_add_from_invite_link_access)
            .chain(add_members_pending_admin_approval)
            .chain(delete_members_pending_admin_approval)
            .chain(promote_members_pending_admin_approval)
            .chain(modify_invite_link_password)
            .chain(modify_announcements_only)
            .chain(modify_member_labels)
            .chain(modify_member_label_access)
            .collect();

        Ok(GroupChanges {
            group_id: group_id
                .try_into()
                .map_err(|_| GroupDecodingError::WrongBlob)?,
            editor: source_user_id,
            version,
            changes: changes?,
            change_epoch,
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
