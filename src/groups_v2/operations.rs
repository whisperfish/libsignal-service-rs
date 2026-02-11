use std::convert::TryInto;

use base64::prelude::*;
use bytes::Bytes;
use libsignal_protocol::{Aci, Pni, ServiceId};
use prost::Message;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{
        AnyProfileKeyCredentialPresentation, ExpiringProfileKeyCredential,
        ProfileKey,
    },
    ServerPublicParams,
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
        AccessControl, BannedMember, GroupCandidate, Member, PendingMember,
        PromotedMember, RequestingMember,
    },
    Group, GroupChange, GroupChanges,
};

pub struct GroupOperations {
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
    fn encrypt_service_id(
        &self,
        service_id: ServiceId,
    ) -> Result<Vec<u8>, GroupDecodingError> {
        let ciphertext = self.group_secret_params.encrypt_service_id(service_id);
        Ok(zkgroup::serialize(&ciphertext))
    }

    fn decrypt_service_id(
        &self,
        ciphertext: &[u8],
    ) -> Result<ServiceId, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
        {
            ServiceId::Aci(aci) => Ok(ServiceId::from(aci)),
            ServiceId::Pni(pni) => Ok(ServiceId::from(pni)),
        }
    }

    fn encrypt_aci(&self, aci: Aci) -> Result<Vec<u8>, GroupDecodingError> {
        let ciphertext =
            self.group_secret_params.encrypt_service_id(aci.into());
        Ok(zkgroup::serialize(&ciphertext))
    }

    fn decrypt_aci(
        &self,
        ciphertext: &[u8],
    ) -> Result<Aci, GroupDecodingError> {
        match self
            .group_secret_params
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
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
            .decrypt_service_id(zkgroup::deserialize(ciphertext)?)?
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

    fn encrypt_profile_key(
        &self,
        profile_key: ProfileKey,
        aci: Aci,
    ) -> Result<Vec<u8>, GroupDecodingError> {
        let ciphertext =
            self.group_secret_params.encrypt_profile_key(profile_key, aci);
        Ok(zkgroup::serialize(&ciphertext))
    }

    fn decrypt_profile_key(
        &self,
        encrypted_profile_key: &[u8],
        decrypted_aci: libsignal_protocol::Aci,
    ) -> Result<ProfileKey, GroupDecodingError> {
        Ok(self.group_secret_params.decrypt_profile_key(
            zkgroup::deserialize(encrypted_profile_key)?,
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
        member: &proto::group_change::actions::PromotePendingPniAciMemberProfileKeyAction,
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
            joined_at_revision: member.joined_at_revision,
        })
    }

    fn decrypt_pending_member(
        &self,
        member: proto::PendingMember,
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
        member: proto::RequestingMember,
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
        member: proto::BannedMember,
    ) -> Result<BannedMember, GroupDecodingError> {
        Ok(BannedMember {
            service_id: self.decrypt_service_id(&member.user_id)?,
            timestamp: member.timestamp,
        })
    }

    fn encrypt_blob<R: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness);
        self.group_secret_params.encrypt_blob(randomness, plaintext)
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

    pub fn encrypt_title<R: rand::Rng + rand::CryptoRng>(
        &self,
        title: &str,
        rng: &mut R,
    ) -> Vec<u8> {
        let blob = GroupAttributeBlob {
            content: Some(group_attribute_blob::Content::Title(
                title.to_string(),
            )),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // 4-byte prefix
        blob.encode(&mut buf).expect("encoding should succeed");
        self.encrypt_blob(&buf, rng)
    }

    fn encrypt_description<R: rand::Rng + rand::CryptoRng>(
        &self,
        description: &str,
        rng: &mut R,
    ) -> Vec<u8> {
        let blob = GroupAttributeBlob {
            content: Some(group_attribute_blob::Content::Description(
                description.to_string(),
            )),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // 4-byte prefix
        blob.encode(&mut buf).expect("encoding should succeed");
        self.encrypt_blob(&buf, rng)
    }

    fn encrypt_disappearing_message_timer<R: rand::Rng + rand::CryptoRng>(
        &self,
        timer: &Timer,
        rng: &mut R,
    ) -> Vec<u8> {
        let blob = GroupAttributeBlob {
            content: Some(
                group_attribute_blob::Content::DisappearingMessagesDuration(
                    timer.duration,
                ),
            ),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 4]); // 4-byte prefix
        blob.encode(&mut buf).expect("encoding should succeed");
        self.encrypt_blob(&buf, rng)
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
    ) -> Result<Group, GroupDecodingError> {
        // Destructuring to catch any future changes
        let proto::Group {
            public_key: _,
            title,
            avatar,
            disappearing_messages_timer,
            access_control,
            revision,
            members,
            pending_members,
            requesting_members,
            invite_link_password,
            description,
            announcements_only,
            banned_members,
        } = group;

        let title = self.decrypt_title(&title);

        let description = self.decrypt_description(&description);

        let disappearing_messages_timer = self
            .decrypt_disappearing_message_timer(&disappearing_messages_timer);

        let members = members
            .into_iter()
            .map(|m| self.decrypt_member(m))
            .collect::<Result<_, _>>()?;

        let pending_members = pending_members
            .into_iter()
            .map(|m| self.decrypt_pending_member(m))
            .collect::<Result<_, _>>()?;

        let requesting_members = requesting_members
            .into_iter()
            .map(|m| self.decrypt_requesting_member(m))
            .collect::<Result<_, _>>()?;

        let banned_members = banned_members
            .into_iter()
            .map(|m| self.decrypt_banned_member(m))
            .collect::<Result<_, _>>()?;

        let access_control =
            access_control.map(TryInto::try_into).transpose()?;

        Ok(Group {
            title,
            avatar,
            disappearing_messages_timer,
            access_control,
            revision,
            members,
            pending_members,
            requesting_members,
            invite_link_password,
            description,
            announcements_only,
            banned_members,
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
            source_service_id,
            revision,
            add_members,
            delete_members,
            modify_member_roles,
            modify_member_profile_keys,
            add_pending_members,
            delete_pending_members,
            promote_pending_members,
            modify_title,
            modify_avatar,
            modify_disappearing_messages_timer,
            modify_attributes_access,
            modify_member_access,
            modify_add_from_invite_link_access,
            add_requesting_members,
            delete_requesting_members,
            promote_requesting_members,
            modify_invite_link_password,
            modify_description,
            modify_announcements_only,
            add_banned_members,
            delete_banned_members,
            promote_pending_pni_aci_members,
        } = Message::decode(Bytes::from(actions))?;

        let editor = self.decrypt_aci(&source_service_id)?;

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

        let add_pending_members = add_pending_members
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewPendingMember(
                    self.decrypt_pending_member(added)?,
                ))
            });

        let delete_pending_members =
            delete_pending_members.into_iter().map(|m| {
                Ok(GroupChange::DeletePendingMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_pending_members =
            promote_pending_members.into_iter().map(|m| {
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
                self.decrypt_description(&m.description),
            ))
        });

        let modify_disappearing_messages_timer =
            modify_disappearing_messages_timer.into_iter().map(|m| {
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

        let add_banned_members = add_banned_members
            .into_iter()
            .filter_map(|m| m.added)
            .map(|m| {
                Ok(GroupChange::AddBannedMember(self.decrypt_banned_member(m)?))
            });

        let delete_banned_members =
            delete_banned_members.into_iter().map(|m| {
                Ok(GroupChange::DeleteBannedMember(
                    self.decrypt_service_id(&m.deleted_user_id)?,
                ))
            });

        let promote_pending_member =
            promote_pending_pni_aci_members.into_iter().map(|m| {
                let promoted =
                    self.decrypt_pni_aci_promotion_presentation(&m)?;
                Ok(GroupChange::PromotePendingPniAciMemberProfileKey(promoted))
            });

        let modify_add_from_invite_link_access =
            modify_add_from_invite_link_access.into_iter().map(|m| {
                Ok(GroupChange::InviteLinkAccess(
                    m.add_from_invite_link_access.try_into()?,
                ))
            });

        let add_requesting_members = add_requesting_members
            .into_iter()
            .filter_map(|m| m.added)
            .map(|added| {
                Ok(GroupChange::NewRequestingMember(
                    self.decrypt_requesting_member(added)?,
                ))
            });

        let delete_requesting_members =
            delete_requesting_members.into_iter().map(|m| {
                Ok(GroupChange::DeleteRequestingMember(
                    self.decrypt_aci(&m.deleted_user_id)?,
                ))
            });

        let promote_requesting_members =
            promote_requesting_members.into_iter().map(|m| {
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

        let changes: Result<Vec<GroupChange>, GroupDecodingError> = new_members
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
            .chain(add_banned_members)
            .chain(delete_banned_members)
            .chain(promote_pending_member)
            .chain(modify_add_from_invite_link_access)
            .chain(add_requesting_members)
            .chain(delete_requesting_members)
            .chain(promote_requesting_members)
            .chain(modify_invite_link_password)
            .chain(modify_announcements_only)
            .collect();

        Ok(GroupChanges {
            group_id: group_id
                .try_into()
                .map_err(|_| GroupDecodingError::WrongBlob)?,
            editor,
            revision,
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

    /// Encrypt a Group proto for creation
    pub fn encrypt_group<R: rand::Rng + rand::CryptoRng>(
        &self,
        group: &Group,
        rng: &mut R,
    ) -> Result<proto::Group, GroupDecodingError> {
        let encrypted_title = self.encrypt_title(&group.title, rng);
        let encrypted_description = group
            .description
            .as_ref()
            .map(|d| self.encrypt_description(d, rng))
            .unwrap_or_default();
        let encrypted_timer = group
            .disappearing_messages_timer
            .as_ref()
            .map(|t| self.encrypt_disappearing_message_timer(t, rng))
            .unwrap_or_default();

        let encrypted_members = group
            .members
            .iter()
            .map(|m| {
                Ok(proto::Member {
                    user_id: self.encrypt_aci(m.aci)?,
                    profile_key: self.encrypt_profile_key(m.profile_key, m.aci)?,
                    presentation: vec![], // Not needed for stored group
                    role: m.role.into(),
                    joined_at_revision: m.joined_at_revision,
                })
            })
            .collect::<Result<Vec<_>, GroupDecodingError>>()?;

        let access_control = group.access_control.as_ref().map(|ac| {
            proto::AccessControl {
                attributes: ac.attributes.into(),
                members: ac.members.into(),
                add_from_invite_link: ac.add_from_invite_link.into(),
            }
        });

        Ok(proto::Group {
            public_key: zkgroup::serialize(
                &self.group_secret_params.get_public_params(),
            ),
            title: encrypted_title,
            avatar: group.avatar.clone(),
            disappearing_messages_timer: encrypted_timer,
            access_control,
            revision: group.revision,
            members: encrypted_members,
            pending_members: vec![],
            requesting_members: vec![],
            invite_link_password: group.invite_link_password.clone(),
            description: encrypted_description,
            announcements_only: group.announcements_only,
            banned_members: vec![],
        })
    }

    /// Build an AddMemberAction for a GroupChange
    pub fn build_add_member_action(
        &self,
        aci: Aci,
        profile_key: ProfileKey,
        role: super::model::Role,
    ) -> Result<proto::group_change::actions::AddMemberAction, GroupDecodingError>
    {
        Ok(proto::group_change::actions::AddMemberAction {
            added: Some(proto::Member {
                user_id: self.encrypt_aci(aci)?,
                profile_key: self.encrypt_profile_key(profile_key, aci)?,
                presentation: vec![],
                role: role.into(),
                joined_at_revision: 0, // Set by server
            }),
            join_from_invite_link: false,
        })
    }

    /// Build a DeleteMemberAction for a GroupChange
    pub fn build_remove_member_action(
        &self,
        aci: Aci,
    ) -> Result<proto::group_change::actions::DeleteMemberAction, GroupDecodingError>
    {
        Ok(proto::group_change::actions::DeleteMemberAction {
            deleted_user_id: self.encrypt_aci(aci)?,
        })
    }

    /// Create a presentation from a credential for adding a member to a group.
    ///
    /// This creates a ZK proof (ExpiringProfileKeyCredentialPresentation) that the
    /// Signal server can verify to validate the member's identity and profile key.
    pub fn create_member_presentation(
        &self,
        server_public_params: &ServerPublicParams,
        credential: &ExpiringProfileKeyCredential,
    ) -> Vec<u8> {
        let randomness: [u8; 32] = rand::random();
        let presentation = server_public_params
            .create_expiring_profile_key_credential_presentation(
                randomness,
                self.group_secret_params,
                *credential,
            );
        zkgroup::serialize(&presentation)
    }

    /// Encrypt a group for creation, using credentials for member presentations.
    ///
    /// This method properly populates the `presentation` field for members with
    /// credentials, which is required by the Signal server for group creation.
    ///
    /// Members with credentials get added with presentations (full members).
    /// Members without credentials get added as pending invites.
    ///
    /// # Arguments
    /// * `title` - The group title
    /// * `description` - Optional group description
    /// * `disappearing_messages_timer` - Optional disappearing messages timer
    /// * `access_control` - Optional access control settings
    /// * `self_credential` - The creator's own credential (required)
    /// * `member_candidates` - Other members to add, with optional credentials
    /// * `server_public_params` - Server public params for creating presentations
    /// * `rng` - Random number generator
    pub fn encrypt_group_with_credentials<R: rand::Rng + rand::CryptoRng>(
        &self,
        title: &str,
        description: Option<&str>,
        disappearing_messages_timer: Option<&Timer>,
        access_control: Option<&AccessControl>,
        self_credential: &ExpiringProfileKeyCredential,
        member_candidates: &[GroupCandidate],
        server_public_params: &ServerPublicParams,
        rng: &mut R,
    ) -> Result<proto::Group, GroupDecodingError> {
        let mut members = Vec::new();
        let mut pending_members = Vec::new();

        // Add self as administrator with presentation
        let self_presentation =
            self.create_member_presentation(server_public_params, self_credential);
        members.push(proto::Member {
            user_id: vec![],      // Server extracts from presentation
            profile_key: vec![],  // Server extracts from presentation
            presentation: self_presentation,
            role: proto::member::Role::Administrator.into(),
            joined_at_revision: 0,
        });

        // Add other members
        for candidate in member_candidates {
            if let Some(credential) = &candidate.credential {
                // Has credential - add as full member with presentation
                let presentation =
                    self.create_member_presentation(server_public_params, credential);
                members.push(proto::Member {
                    user_id: vec![],
                    profile_key: vec![],
                    presentation,
                    role: proto::member::Role::Default.into(),
                    joined_at_revision: 0,
                });
            } else {
                // No credential - add as pending invite
                let user_id_ciphertext =
                    self.encrypt_service_id(candidate.service_id)?;
                let self_aci = self_credential.aci();
                pending_members.push(proto::PendingMember {
                    member: Some(proto::Member {
                        user_id: user_id_ciphertext,
                        profile_key: vec![],
                        presentation: vec![],
                        role: proto::member::Role::Default.into(),
                        joined_at_revision: 0,
                    }),
                    added_by_user_id: self.encrypt_aci(self_aci)?,
                    timestamp: 0, // Server sets
                });
            }
        }

        // Encrypt title, description, timer
        let encrypted_title = self.encrypt_title(title, rng);
        let encrypted_description = description
            .map(|d| self.encrypt_description(d, rng))
            .unwrap_or_default();
        let encrypted_timer = disappearing_messages_timer
            .map(|t| self.encrypt_disappearing_message_timer(t, rng))
            .unwrap_or_default();

        // Convert access control
        let proto_access_control = access_control.map(|ac| proto::AccessControl {
            attributes: ac.attributes.into(),
            members: ac.members.into(),
            add_from_invite_link: ac.add_from_invite_link.into(),
        });

        Ok(proto::Group {
            public_key: zkgroup::serialize(
                &self.group_secret_params.get_public_params(),
            ),
            title: encrypted_title,
            avatar: String::new(),
            disappearing_messages_timer: encrypted_timer,
            access_control: proto_access_control,
            revision: 0,
            members,
            pending_members,
            requesting_members: vec![],
            invite_link_password: vec![],
            description: encrypted_description,
            announcements_only: false,
            banned_members: vec![],
        })
    }

    /// Build an AddMemberAction with a credential presentation for a GroupChange.
    ///
    /// This is used when adding members to an existing group with proper ZK proofs.
    pub fn build_add_member_action_with_credential(
        &self,
        credential: &ExpiringProfileKeyCredential,
        role: super::model::Role,
        server_public_params: &ServerPublicParams,
    ) -> proto::group_change::actions::AddMemberAction {
        let presentation =
            self.create_member_presentation(server_public_params, credential);
        proto::group_change::actions::AddMemberAction {
            added: Some(proto::Member {
                user_id: vec![],      // Server extracts from presentation
                profile_key: vec![],  // Server extracts from presentation
                presentation,
                role: role.into(),
                joined_at_revision: 0, // Set by server
            }),
            join_from_invite_link: false,
        }
    }
}
