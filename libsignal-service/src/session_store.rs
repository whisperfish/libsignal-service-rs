use libsignal_protocol::{ProtocolAddress, SessionStore, SignalProtocolError};

/// This is additional functions required to handle
/// session deletion. It might be a candidate for inclusion into
/// the bigger `SessionStore` trait.
pub trait SessionStoreExt: SessionStore {
    /// Use this to downcast as a regular `SessionStore`
    fn as_mut_session_store(&mut self) -> &mut dyn SessionStore;

    /// Get the IDs of all known devices with active sessions for a recipient.
    fn get_sub_device_sessions(
        &self,
        name: &str,
    ) -> Result<Vec<u32>, SignalProtocolError>;

    /// Remove a session record for a recipient ID + device ID tuple.
    fn delete_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    fn delete_all_sessions(
        &self,
        address: &str,
    ) -> Result<usize, SignalProtocolError>;
}
