pub use crate::{
    models::Message,
    proto::{CallMessage, ReceiptMessage, SyncMessage, TypingMessage},
};

pub struct Metadata {
    pub sender: crate::ServiceAddress,
    pub sender_device: i32,
    pub timestamp: u64,
    pub needs_receipt: bool,
}

pub struct Content {
    pub sender: crate::ServiceAddress,
    pub sender_device: i32,
    pub timestamp: u64,
    pub needs_receipt: bool,
    pub body: ContentBody,
}

impl Content {
    pub fn from_body(body: impl Into<ContentBody>, metadata: Metadata) -> Self {
        Self {
            body: body.into(),
            sender: metadata.sender,
            sender_device: metadata.sender_device,
            timestamp: metadata.timestamp,
            needs_receipt: metadata.needs_receipt,
        }
    }
}

pub enum ContentBody {
    DataMessage(Message),
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

impl_from_for_content_body!(DataMessage(Message));
impl_from_for_content_body!(SynchronizeMessage(SyncMessage));
impl_from_for_content_body!(CallMessage(CallMessage));
impl_from_for_content_body!(ReceiptMessage(ReceiptMessage));
impl_from_for_content_body!(TypingMessage(TypingMessage));
