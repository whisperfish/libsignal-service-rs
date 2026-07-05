use chrono::Utc;
use libsignal_core::DeviceId;
use libsignal_protocol::{ProtocolAddress, ServiceId};
use prost::Message;
use std::fmt;
use uuid::Uuid;

pub use crate::{
    proto::{
        attachment_pointer::Flags as AttachmentPointerFlags,
        data_message::Flags as DataMessageFlags, data_message::Reaction,
        sync_message, AttachmentPointer, CallMessage, DataMessage,
        DecryptionErrorMessage, EditMessage, GroupContextV2, NullMessage,
        PniSignatureMessage, ReceiptMessage, StoryMessage, SyncMessage,
        TypingMessage,
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
    pub client_timestamp: chrono::DateTime<Utc>,
    pub server_timestamp: chrono::DateTime<Utc>,
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
            "Metadata {{ sender: {}, guid: {}, server timestamp: {} }}",
            self.sender.service_id_string(),
            // XXX: should this still be optional?
            self.server_guid
                .map(|u| u.to_string())
                .as_deref()
                .unwrap_or("None"),
            self.server_timestamp,
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
        let Some(content) = p.content else {
            return Err(ServiceError::UnsupportedContent);
        };

        use crate::proto::content::Content;
        match content {
            Content::DataMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::SyncMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::CallMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::NullMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::ReceiptMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::TypingMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::DecryptionErrorMessage(msg) => Ok(Self {
                metadata,
                body: ContentBody::DecryptionErrorMessage(
                    DecryptionErrorMessage::decode(msg.as_ref())?,
                ),
            }),
            Content::StoryMessage(msg) => Ok(Self::from_body(msg, metadata)),
            Content::EditMessage(msg) => Ok(Self::from_body(msg, metadata)),
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
            Self::DecryptionErrorMessage(_) => {
                write!(f, "DecryptionErrorMessage")
            },
            Self::StoryMessage(_) => write!(f, "StoryMessage"),
            #[allow(deprecated)]
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
    DecryptionErrorMessage(DecryptionErrorMessage),
    StoryMessage(StoryMessage),
    #[deprecated = "PNI signature messages are constructed as side-car during message delivery"]
    PniSignatureMessage(PniSignatureMessage),
    EditMessage(EditMessage),
}

impl NullMessage {
    pub fn generate<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        // Random length between 1 and 140 bytes
        let padding_length = (rng.next_u64() % 140) as usize + 1;
        let mut padding = vec![0; padding_length];
        rng.fill(padding.as_mut_slice());
        NullMessage {
            padding: Some(padding),
        }
    }
}

impl ContentBody {
    pub fn into_proto(self) -> crate::proto::Content {
        use crate::proto::content::Content;

        let inner = match self {
            Self::NullMessage(msg) => Content::NullMessage(msg),
            Self::DataMessage(msg) => Content::DataMessage(msg),
            Self::SynchronizeMessage(msg) => Content::SyncMessage(msg),
            Self::CallMessage(msg) => Content::CallMessage(msg),
            Self::ReceiptMessage(msg) => Content::ReceiptMessage(msg),
            Self::TypingMessage(msg) => Content::TypingMessage(msg),
            Self::DecryptionErrorMessage(msg) => {
                Content::DecryptionErrorMessage(msg.encode_to_vec())
            },
            Self::StoryMessage(msg) => Content::StoryMessage(msg),
            #[allow(deprecated)]
            Self::PniSignatureMessage(msg) => {
                tracing::warn!("manually constructed PniSignatureMessage");
                return crate::proto::Content {
                    content: None,
                    sender_key_distribution_message: None,
                    // PNI signature gets added down the message sender stream
                    pni_signature_message: Some(msg),
                };
            },
            Self::EditMessage(msg) => Content::EditMessage(msg),
        };
        crate::proto::Content {
            content: Some(inner),
            // TODO: handle SKDM; ideally this is also "tacked on" when needed,
            // and not handled as a separate message.
            sender_key_distribution_message: None,
            // PNI signature gets added down the message sender stream
            pni_signature_message: None,
        }
    }
}

macro_rules! impl_from_for_content_body {
    ($enum:ident ($t:ty)) => {
        impl From<$t> for ContentBody {
            fn from(inner: $t) -> ContentBody {
                // Remove #[allow(deprecated)] when PniSignatureMessage is removed.
                #[allow(deprecated)]
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
