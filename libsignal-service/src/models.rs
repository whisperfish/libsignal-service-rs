use std::convert::TryInto;

use crate::proto::Verified;

use bytes::Bytes;
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

/// Attachment represents an attachment received from a peer
#[derive(Debug, Serialize, Deserialize)]
pub struct Attachment<R> {
    pub content_type: String,
    pub reader: R,
}

/// Mirror of the protobuf ContactDetails message
/// but with stronger types (e.g. `ServiceAddress` instead of optional uuid and string phone numbers)
/// and some helper functions
#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    pub uuid: Uuid,
    pub phone_number: Option<PhoneNumber>,
    pub name: String,
    pub color: Option<String>,
    #[serde(skip)]
    pub verified: Verified,
    pub profile_key: Vec<u8>,
    pub expire_timer: u32,
    pub expire_timer_version: u32,
    pub inbox_position: u32,
    pub archived: bool,
    #[serde(skip)]
    pub avatar: Option<Attachment<Bytes>>,
}

#[derive(Error, Debug)]
pub enum ParseContactError {
    #[error(transparent)]
    Protobuf(#[from] prost::DecodeError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error("missing UUID")]
    MissingUuid,
    #[error("missing profile key")]
    MissingProfileKey,
    #[error("missing avatar content-type")]
    MissingAvatarContentType,
}

impl Contact {
    pub fn from_proto(
        contact_details: crate::proto::ContactDetails,
        avatar_data: Option<Bytes>,
    ) -> Result<Self, ParseContactError> {
        Ok(Self {
            uuid: contact_details
                .aci
                .as_ref()
                .ok_or(ParseContactError::MissingUuid)?
                .parse()?,
            phone_number: contact_details
                .number
                .as_ref()
                .and_then(|n| phonenumber::parse(None, n).ok()),
            name: contact_details.name().into(),
            color: contact_details.color.clone(),
            verified: contact_details.verified.clone().unwrap_or_default(),
            profile_key: contact_details.profile_key().to_vec(),
            expire_timer: contact_details.expire_timer(),
            expire_timer_version: contact_details.expire_timer_version(),
            inbox_position: contact_details.inbox_position(),
            archived: contact_details.archived(),
            avatar: contact_details.avatar.and_then(|avatar| {
                if let (Some(content_type), Some(avatar_data)) =
                    (avatar.content_type, avatar_data)
                {
                    Some(Attachment {
                        content_type,
                        reader: avatar_data,
                    })
                } else {
                    tracing::warn!("missing avatar content-type, skipping.");
                    None
                }
            }),
        })
    }

    pub fn profile_key(&self) -> Result<ProfileKey, ParseContactError> {
        Ok(ProfileKey::create(
            self.profile_key
                .clone()
                .try_into()
                .map_err(|_| ParseContactError::MissingProfileKey)?,
        ))
    }
}
