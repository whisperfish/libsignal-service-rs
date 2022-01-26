use bytes::Bytes;
use prost::Message;
use zkgroup::{
    groups::GroupSecretParams,
    profiles::{ProfileKey, ProfileKeyCredentialPresentation},
};

use crate::proto::{
    group_attribute_blob, DecryptedGroup, DecryptedMember,
    DecryptedPendingMember, DecryptedRequestingMember, DecryptedTimer,
    Group as EncryptedGroup, GroupAttributeBlob, Member as EncryptedMember,
    PendingMember as EncryptedPendingMember,
    RequestingMember as EncryptedRequestingMember,
};

pub(crate) struct GroupOperations {
    group_secret_params: GroupSecretParams,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupDecryptionError {
    #[error("zero-knowledge group error")]
    ZkGroupError,
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
    #[error("protobuf message decoding error: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("wrong group attribute blob")]
    WrongBlob,
}

impl From<zkgroup::ZkGroupError> for GroupDecryptionError {
    fn from(_: zkgroup::ZkGroupError) -> Self {
        GroupDecryptionError::ZkGroupError
    }
}

impl GroupOperations {
    fn decrypt_uuid(
        &self,
        uuid: &[u8],
    ) -> Result<[u8; 16], GroupDecryptionError> {
        let bytes = self
            .group_secret_params
            .decrypt_uuid(bincode::deserialize(uuid)?)
            .map_err(|_| GroupDecryptionError::ZkGroupError)?;
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
            let profile_key_credential_presentation: ProfileKeyCredentialPresentation = bincode::deserialize(&member.presentation)?;
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

    fn decrypt_pending_member(
        &self,
        member: EncryptedPendingMember,
    ) -> Result<DecryptedPendingMember, GroupDecryptionError> {
        let inner_member =
            member.member.ok_or(GroupDecryptionError::WrongBlob)?;
        // "Unknown" UUID with zeroes in case of errors, see: UuidUtil.java:16
        let uuid = self.decrypt_uuid(&inner_member.user_id).unwrap_or_default();
        let added_by = self.decrypt_uuid(&member.added_by_user_id)?;

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
            let profile_key_credential_presentation: ProfileKeyCredentialPresentation = bincode::deserialize(&member.presentation)?;
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
                .map_err(|_| GroupDecryptionError::ZkGroupError)
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
