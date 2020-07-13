/// Attachment represents an attachment received from a peer
///
/// Source: `textsecure/textsecure.go`
pub struct Attachment<R> {
    pub reader: R,
    pub mime_type: String,
}

/// Group holds group metadata
///
/// Source: `textsecure/groups.go`
pub struct Group {
    pub id: Vec<u8>,
    pub hex_id: String,
    pub flags: u32,
    pub name: String,
    pub members: Vec<String>,
    pub avatar: Option<Vec<u8>>,
}

/// Message represents a message received from the peer.
///
/// It can optionally include attachments and be sent to a group.
///
/// Source: `textsecure/textsecure.go`
pub struct Message {
    pub source: String,
    pub message: String,
    pub attachments: Vec<Attachment<u8>>,
    pub group: Option<Group>,
    pub timestamp: u64,
    pub flags: u32,
}
