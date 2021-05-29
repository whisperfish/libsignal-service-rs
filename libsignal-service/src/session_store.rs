use libsignal_protocol::{ProtocolAddress, SessionStore, SignalProtocolError};

/// This is additional functions required to handle
/// session deletion. It might be a candidate for inclusion into
/// the bigger `SessionStore` trait.
#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
pub trait SessionStoreExt: SessionStore {
    /// Get the IDs of all known devices with active sessions for a recipient.
    async fn get_sub_device_sessions(
        &self,
        name: &str,
    ) -> Result<Vec<u32>, SignalProtocolError>;

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    async fn delete_all_sessions(
        &self,
        address: &str,
    ) -> Result<usize, SignalProtocolError>;
}
