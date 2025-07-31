#![recursion_limit = "256"]
#![deny(clippy::dbg_macro)]
// TODO: we cannot use this until whisperfish builds with a newer Rust version
#![allow(clippy::uninlined_format_args)]

mod account_manager;
pub mod attachment_cipher;
pub mod cipher;
pub mod profile_cipher;
pub mod sticker_cipher;

pub mod configuration;
pub mod content;
mod digeststream;
pub mod envelope;
pub mod groups_v2;
pub mod master_key;
pub mod messagepipe;
pub mod models;
pub mod pre_keys;
pub mod profile_name;
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod proto;
pub mod provisioning;
pub mod push_service;
pub mod receiver;
pub mod sender;
pub mod service_address;
pub mod session_store;
mod timestamp;
pub mod unidentified_access;
pub mod utils;
pub mod websocket;

pub use crate::account_manager::{
    decrypt_device_name, AccountManager, Profile, ProfileManagerError,
};
pub use crate::service_address::*;

pub const USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

/// GROUP_UPDATE_FLAG signals that this message updates the group membership or
/// name.
pub const GROUP_UPDATE_FLAG: u32 = 1;

/// GROUP_LEAVE_FLAG signals that this message is a group leave message.
pub const GROUP_LEAVE_FLAG: u32 = 2;

pub mod prelude {
    pub use crate::{
        cipher::ServiceCipher,
        configuration::{
            ServiceConfiguration, ServiceCredentials, SignalingKey,
        },
        content::Content,
        envelope::Envelope,
        groups_v2::{
            AccessControl, Group, Member, PendingMember, RequestingMember,
            Timer,
        },
        master_key::{MasterKey, MasterKeyStore, StorageServiceKey},
        proto::{
            attachment_pointer::AttachmentIdentifier, sync_message::Contacts,
            AttachmentPointer,
        },
        push_service::{PushService, ServiceError},
        receiver::MessageReceiver,
        sender::{MessageSender, MessageSenderError},
        session_store::SessionStoreExt,
    };
    pub use phonenumber;
    pub use prost::Message as ProtobufMessage;
    pub use uuid::{Error as UuidError, Uuid};
    pub use zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
    };

    pub use libsignal_core::InvalidDeviceId;
    pub use libsignal_protocol::{DeviceId, IdentityKeyStore};
}

pub use libsignal_protocol as protocol;
pub use zkgroup;
