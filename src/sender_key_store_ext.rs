use async_trait::async_trait;
use libsignal_protocol::{
    ProtocolAddress, SenderKeyStore, SignalProtocolError,
};
use uuid::Uuid;

/// Additional functions for managing per-recipient sender-key "shared" state.
#[async_trait(?Send)]
pub trait SenderKeyStoreExt: SenderKeyStore {
    /// Check whether a given distribution_id was marked as shared to a given recipient.
    async fn is_sender_key_shared(
        &self,
        distribution_id: Uuid,
        recipient: &ProtocolAddress,
    ) -> Result<bool, SignalProtocolError>;

    /// Mark `distribution_id` as having been shared with `recipient`.
    async fn mark_sender_key_shared(
        &mut self,
        distribution_id: Uuid,
        recipient: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;

    /// Clear the shared mark for `distribution_id` + `recipient`.
    async fn clear_sender_key_shared(
        &mut self,
        distribution_id: Uuid,
        recipient: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;

    /// Clear the shared mark for ALL recipients of `distribution_id`.
    async fn clear_all_sender_key_shared(
        &mut self,
        distribution_id: Uuid,
    ) -> Result<(), SignalProtocolError>;

    /// Clear the shared mark for ALL distribution_ids for `recipient`.
    async fn clear_sender_key_shared_for_address(
        &mut self,
        recipient: &ProtocolAddress,
    ) -> Result<(), SignalProtocolError>;
}
