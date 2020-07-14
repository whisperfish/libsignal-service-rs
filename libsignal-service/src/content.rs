pub use crate::{
    proto::{
        CallMessage, DataMessage, ReceiptMessage, SyncMessage, TypingMessage,
    },
    push_service::ServiceError,
};

pub struct Metadata {
    pub sender: crate::ServiceAddress,
    pub sender_device: u32,
    pub timestamp: u64,
    pub needs_receipt: bool,
}

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

pub enum ContentBody {
    DataMessage(DataMessage),
    SynchronizeMessage(SyncMessage),
    CallMessage(CallMessage),
    ReceiptMessage(ReceiptMessage),
    TypingMessage(TypingMessage),
}

macro_rules! impl_from_for_content_body {
    ($enum:ident ($t:ty)) => {
        impl From<$t> for ContentBody {
            fn from(inner: $t) -> ContentBody { ContentBody::$enum(inner) }
        }
    };
}

impl_from_for_content_body!(DataMessage(DataMessage));
impl_from_for_content_body!(SynchronizeMessage(SyncMessage));
impl_from_for_content_body!(CallMessage(CallMessage));
impl_from_for_content_body!(ReceiptMessage(ReceiptMessage));
impl_from_for_content_body!(TypingMessage(TypingMessage));
