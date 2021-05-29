#![recursion_limit = "256"]
#![deny(clippy::dbg_macro)]

mod account_manager;
pub mod attachment_cipher;
pub mod cipher;
pub mod profile_cipher;
pub mod sealed_session_cipher;

pub mod configuration;
pub mod content;
mod digeststream;
pub mod envelope;
pub mod groups_v2;
pub mod messagepipe;
pub mod models;
pub mod pre_keys;
pub mod profile_name;
pub mod proto;
pub mod provisioning;
pub mod push_service;
pub mod receiver;
pub mod sender;
pub mod service_address;
mod session_store;
pub mod utils;

pub use crate::account_manager::{
    AccountManager, Profile, ProfileManagerError,
};
pub use crate::service_address::*;

pub const USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

/// GROUP_UPDATE_FLAG signals that this message updates the group membership or
/// name.
pub const GROUP_UPDATE_FLAG: u32 = 1;

/// GROUP_LEAVE_FLAG signals that this message is a group leave message.
pub const GROUP_LEAVE_FLAG: u32 = 2;

/// This trait allows for the conditional support of Send compatible futures
/// depending on whether or not the `unsend-futures` feature flag is enabled.
/// As this feature is disabled by default, Send is supported by default.
///
/// This is necessary as actix does not support Send, which means unconditionally
/// imposing this requirement would break libsignal-service-actix.
///
/// Conversely, hyper does support Send, which is why libsignal-service-hyper
/// does not enable the `unsend-futures` feature flag.
#[cfg(not(feature = "unsend-futures"))]
pub trait MaybeSend: Send {}
#[cfg(not(feature = "unsend-futures"))]
impl<T> MaybeSend for T where T: Send {}

#[cfg(feature = "unsend-futures")]
pub trait MaybeSend {}
#[cfg(feature = "unsend-futures")]
impl<T> MaybeSend for T {}

pub mod prelude {
    pub use super::ServiceAddress;
    pub use crate::{
        cipher::ServiceCipher,
        configuration::{
            ServiceConfiguration, ServiceCredentials, SignalingKey,
        },
        content::Content,
        envelope::Envelope,
        proto::{
            attachment_pointer::AttachmentIdentifier, sync_message::Contacts,
            AttachmentPointer,
        },
        push_service::{PushService, ServiceError},
        receiver::MessageReceiver,
        sender::{MessageSender, MessageSenderError},
    };
    pub use phonenumber;
    pub use prost::Message as ProtobufMessage;
    pub use uuid::{Error as UuidError, Uuid};
    pub use zkgroup::groups::{GroupMasterKey, GroupSecretParams};

    pub mod protocol {
        pub use crate::session_store::SessionStoreExt;
        pub use libsignal_protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore,
            KeyPair, PreKeyRecord, PreKeyStore, PrivateKey, ProtocolAddress,
            PublicKey, SessionRecord, SessionStore, SignalProtocolError,
            SignedPreKeyRecord, SignedPreKeyStore,
        };
    }
}
