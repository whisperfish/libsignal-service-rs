use crate::{proto::Verified, ParseServiceAddressError, ServiceAddress};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub address: ServiceAddress,
    pub name: String,
    pub color: Option<String>,
    #[serde(skip)]
    pub verified: Verified,
    pub profile_key: Vec<u8>,
    pub blocked: bool,
    pub expire_timer: u32,
    pub inbox_position: u32,
    pub archived: bool,
    #[serde(skip)]
    pub avatar: Option<Attachment<Bytes>>,
}

#[derive(Error, Debug)]
pub enum ParseContactError {
    #[error(transparent)]
    ProtobufError(#[from] prost::DecodeError),
    #[error(transparent)]
    ServiceAddress(#[from] ParseServiceAddressError),
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
            address: ServiceAddress::parse(
                contact_details.number.as_deref(),
                contact_details.uuid.as_deref(),
            )?,
            name: contact_details.name().into(),
            color: contact_details.color.clone(),
            verified: contact_details.verified.clone().unwrap_or_default(),
            profile_key: contact_details.profile_key().to_vec(),
            blocked: contact_details.blocked(),
            expire_timer: contact_details.expire_timer(),
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
                    log::warn!("missing avatar content-type, skipping.");
                    None
                }
            }),
        })
    }
}
