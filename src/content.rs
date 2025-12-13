use libsignal_core::DeviceId;
use libsignal_protocol::{ProtocolAddress, ServiceId};
use std::fmt;
use uuid::Uuid;

pub use crate::{
    proto::{
        attachment_pointer::Flags as AttachmentPointerFlags,
        data_message::Flags as DataMessageFlags, data_message::Reaction,
        sync_message, AttachmentPointer, CallMessage, DataMessage, EditMessage,
        GroupContextV2, NullMessage, PniSignatureMessage, ReceiptMessage,
        StoryMessage, SyncMessage, TypingMessage,
    },
    push_service::ServiceError,
    ServiceIdExt,
};

mod data_message;
mod story_message;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub sender: ServiceId,
    pub destination: ServiceId,
    pub sender_device: DeviceId,
    pub timestamp: u64,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,
    pub was_plaintext: bool,

    /// A unique UUID for this specific message, produced by the Signal servers.
    ///
    /// The server GUID is used to report spam messages.
    pub server_guid: Option<Uuid>,
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Metadata {{ sender: {}, guid: {} }}",
            self.sender.service_id_string(),
            // XXX: should this still be optional?
            self.server_guid
                .map(|u| u.to_string())
                .as_deref()
                .unwrap_or("None"),
        )
    }
}

impl Metadata {
    pub(crate) fn protocol_address(
        &self,
    ) -> Result<ProtocolAddress, libsignal_core::InvalidDeviceId> {
        self.sender.to_protocol_address(self.sender_device)
    }
}

#[derive(Clone, Debug)]
pub struct Content {
    pub metadata: Metadata,
    pub body: ContentBody,
}

impl Content {
    pub fn from_body(body: impl Into<ContentBody>, metadata: Metadata) -> Self {
        Self {
            metadata,
            body: body.into(),
        }
    }

    /// Converts a proto::Content into a public Content, including metadata.
    pub fn from_proto(
        p: crate::proto::Content,
        metadata: Metadata,
    ) -> Result<Self, ServiceError> {
        // The Java version also assumes only one content type at a time.
        // It's a bit sad that we cannot really match here, we've got no
        // r#type() method.
        // Allow the manual map (if let Some -> option.map(||)), because it
        // reduces the git diff when more types would be added.
        #[allow(clippy::manual_map)]
        if let Some(msg) = p.data_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.sync_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.call_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.receipt_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.typing_message {
            Ok(Self::from_body(msg, metadata))
        // } else if let Some(msg) = p.sender_key_distribution_message {
        //     Ok(Self::from_body(msg, metadata))
        // } else if let Some(msg) = p.decryption_error_message {
        //     Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.story_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.pni_signature_message {
            Ok(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.edit_message {
            Ok(Self::from_body(msg, metadata))
        } else {
            Err(ServiceError::UnsupportedContent)
        }
    }
}

impl fmt::Display for ContentBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullMessage(_) => write!(f, "NullMessage"),
            Self::DataMessage(m) => {
                match (&m.body, &m.reaction, m.attachments.len()) {
                    (Some(body), _, 0) => {
                        write!(f, "DataMessage({})", body)
                    },
                    (Some(body), _, n) => {
                        write!(f, "DataMessage({}, attachments: {n})", body)
                    },
                    (None, Some(emoji), _) => {
                        write!(
                            f,
                            "DataMessage(reaction: {})",
                            emoji.emoji.as_deref().unwrap_or("None")
                        )
                    },
                    (None, _, n) if n > 0 => {
                        write!(f, "DataMessage(attachments: {n})")
                    },
                    _ => {
                        write!(f, "{self:?}")
                    },
                }
            },
            Self::SynchronizeMessage(_) => write!(f, "SynchronizeMessage"),
            Self::CallMessage(_) => write!(f, "CallMessage"),
            Self::ReceiptMessage(_) => write!(f, "ReceiptMessage"),
            Self::TypingMessage(_) => write!(f, "TypingMessage"),
            // Self::SenderKeyDistributionMessage(_) => write!(f, "SenderKeyDistributionMessage"),
            // Self::DecryptionErrorMessage(_) => write!(f, "DecryptionErrorMessage"),
            Self::StoryMessage(_) => write!(f, "StoryMessage"),
            Self::PniSignatureMessage(_) => write!(f, "PniSignatureMessage"),
            Self::EditMessage(_) => write!(f, "EditMessage"),
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ContentBody {
    NullMessage(NullMessage),
    DataMessage(DataMessage),
    SynchronizeMessage(SyncMessage),
    CallMessage(CallMessage),
    ReceiptMessage(ReceiptMessage),
    TypingMessage(TypingMessage),
    // SenderKeyDistributionMessage(SenderKeyDistributionMessage),
    // DecryptionErrorMessage(DecryptionErrorMessage),
    StoryMessage(StoryMessage),
    PniSignatureMessage(PniSignatureMessage),
    EditMessage(EditMessage),
}

impl ContentBody {
    pub fn into_proto(self) -> crate::proto::Content {
        match self {
            Self::NullMessage(msg) => crate::proto::Content {
                null_message: Some(msg),
                ..Default::default()
            },
            Self::DataMessage(msg) => crate::proto::Content {
                data_message: Some(msg),
                ..Default::default()
            },
            Self::SynchronizeMessage(msg) => crate::proto::Content {
                sync_message: Some(msg),
                ..Default::default()
            },
            Self::CallMessage(msg) => crate::proto::Content {
                call_message: Some(msg),
                ..Default::default()
            },
            Self::ReceiptMessage(msg) => crate::proto::Content {
                receipt_message: Some(msg),
                ..Default::default()
            },
            Self::TypingMessage(msg) => crate::proto::Content {
                typing_message: Some(msg),
                ..Default::default()
            },
            // XXX Those two are serialized as Vec<u8> and I'm not currently sure how to handle
            // them.
            // Self::SenderKeyDistributionMessage(msg) => crate::proto::Content {
            //     sender_key_distribution_message: Some(msg),
            //     ..Default::default()
            // },
            // Self::DecryptionErrorMessage(msg) => crate::proto::Content {
            //     decryption_error_message: Some(msg.serialized()),
            //     ..Default::default()
            // },
            Self::StoryMessage(msg) => crate::proto::Content {
                story_message: Some(msg),
                ..Default::default()
            },
            Self::PniSignatureMessage(msg) => crate::proto::Content {
                pni_signature_message: Some(msg),
                ..Default::default()
            },
            Self::EditMessage(msg) => crate::proto::Content {
                edit_message: Some(msg),
                ..Default::default()
            },
        }
    }
}

macro_rules! impl_from_for_content_body {
    ($enum:ident ($t:ty)) => {
        impl From<$t> for ContentBody {
            fn from(inner: $t) -> ContentBody {
                ContentBody::$enum(inner)
            }
        }
    };
}

impl_from_for_content_body!(NullMessage(NullMessage));
impl_from_for_content_body!(DataMessage(DataMessage));
impl_from_for_content_body!(SynchronizeMessage(SyncMessage));
impl_from_for_content_body!(CallMessage(CallMessage));
impl_from_for_content_body!(ReceiptMessage(ReceiptMessage));
impl_from_for_content_body!(TypingMessage(TypingMessage));
// impl_from_for_content_body!(SenderKeyDistributionMessage(
//     SenderKeyDistributionMessage
// ));
// impl_from_for_content_body!(DecryptionErrorMessage(DecryptionErrorMessage));
impl_from_for_content_body!(StoryMessage(StoryMessage));
impl_from_for_content_body!(PniSignatureMessage(PniSignatureMessage));
impl_from_for_content_body!(EditMessage(EditMessage));
