use libsignal_protocol::ProtocolAddress;

pub use crate::{
    proto::{
        attachment_pointer::Flags as AttachmentPointerFlags,
        data_message::Flags as DataMessageFlags, data_message::Reaction,
        group_context::Type as GroupType, sync_message, AttachmentPointer,
        CallMessage, DataMessage, EditMessage, GroupContext, GroupContextV2,
        NullMessage, PniSignatureMessage, ReceiptMessage, StoryMessage,
        SyncMessage, TypingMessage,
    },
    push_service::ServiceError,
};

mod data_message;
mod story_message;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub sender: crate::ServiceAddress,
    pub sender_device: u32,
    pub timestamp: u64,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,
}

impl Metadata {
    pub(crate) fn protocol_address(&self) -> ProtocolAddress {
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
