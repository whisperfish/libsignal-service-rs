pub use crate::{
    proto::{
        attachment_pointer::Flags as AttachmentPointerFlags,
        data_message::Flags as DataMessageFlags, data_message::Reaction,
        group_context::Type as GroupType, sync_message, AttachmentPointer,
        CallMessage, DataMessage, GroupContext, GroupContextV2, ReceiptMessage,
        SyncMessage, TypingMessage,
    },
    push_service::ServiceError,
};

#[derive(Clone, Debug)]
pub struct Metadata {
    pub sender: crate::ServiceAddress,
    pub sender_device: u32,
    pub timestamp: u64,
    pub needs_receipt: bool,
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
    pub(crate) fn from_proto(
        p: crate::proto::Content,
        metadata: Metadata,
    ) -> Option<Self> {
        // The Java version also assumes only one content type at a time.
        // It's a bit sad that we cannot really match here, we've got no
        // r#type() method.
        // Allow the manual map (if let Some -> option.map(||)), because it
        // reduces the git diff when more types would be added.
        #[allow(clippy::manual_map)]
        if let Some(msg) = p.data_message {
            Some(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.sync_message {
            Some(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.call_message {
            Some(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.receipt_message {
            Some(Self::from_body(msg, metadata))
        } else if let Some(msg) = p.typing_message {
            Some(Self::from_body(msg, metadata))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ContentBody {
    DataMessage(DataMessage),
    SynchronizeMessage(SyncMessage),
    CallMessage(CallMessage),
    ReceiptMessage(ReceiptMessage),
    TypingMessage(TypingMessage),
}

impl ContentBody {
    pub fn into_proto(self) -> crate::proto::Content {
        match self {
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

impl_from_for_content_body!(DataMessage(DataMessage));
impl_from_for_content_body!(SynchronizeMessage(SyncMessage));
impl_from_for_content_body!(CallMessage(CallMessage));
impl_from_for_content_body!(ReceiptMessage(ReceiptMessage));
impl_from_for_content_body!(TypingMessage(TypingMessage));
