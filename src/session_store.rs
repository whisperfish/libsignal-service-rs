use async_trait::async_trait;
use libsignal_core::DeviceId;
use libsignal_protocol::{
    ProtocolAddress, ServiceId, SessionStore, SignalProtocolError,
};

use crate::{content::ServiceError, push_service::DEFAULT_DEVICE_ID};

/// This is additional functions required to handle
/// session deletion. It might be a candidate for inclusion into
/// the bigger `SessionStore` trait.
#[async_trait(?Send)]
pub trait SessionStoreExt: SessionStore {
    /// Get the IDs of all known sub devices with active sessions for a recipient.
    ///
    /// This should return every device except for the main device [DEFAULT_DEVICE_ID].
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
    ) -> Result<Vec<DeviceId>, SignalProtocolError>;

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
        address: &ServiceId,
    ) -> Result<usize, SignalProtocolError>;

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_service_addr_device_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<usize, SignalProtocolError> {
        let mut count = 0;
        match self.delete_session(address).await {
            Ok(()) => {
                count += 1;
            },
            Err(SignalProtocolError::SessionNotFound(_)) => (),
            Err(e) => return Err(e),
        }

        Ok(count)
    }

    async fn compute_safety_number(
        &self,
        local_address: &ServiceId,
        address: &ServiceId,
    ) -> Result<String, ServiceError>
    where
        Self: Sized + libsignal_protocol::IdentityKeyStore,
    {
        let addr = crate::cipher::get_preferred_protocol_address(
            self,
            address,
            *DEFAULT_DEVICE_ID,
        )
        .await?;
        let ident = self
            .get_identity(&addr)
            .await?
            .ok_or(SignalProtocolError::UntrustedIdentity(addr))?;
        let local = self
            .get_identity_key_pair()
            .await
            .expect("valid local identity");
        let fp = libsignal_protocol::Fingerprint::new(
            2,
            5200,
            local_address.raw_uuid().as_bytes(),
            local.identity_key(),
            address.raw_uuid().as_bytes(),
            &ident,
        )?;
        Ok(fp.display_string()?)
    }
}
