use libsignal_protocol::{
    Context, ProtocolAddress, SessionStore, SignalProtocolError,
};

use crate::{push_service::DEFAULT_DEVICE_ID, ServiceAddress};

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

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_service_addr_device_session(
        &self,
        address: &ServiceAddress,
        device_id: u32,
    ) -> Result<usize, SignalProtocolError> {
        let mut count = 0;
        if let Some(ref uuid) = address.uuid {
            match self
                .delete_session(&ProtocolAddress::new(
                    uuid.to_string(),
                    device_id.into(),
                ))
                .await
            {
                Ok(()) => {
                    count += 1;
                },
                Err(SignalProtocolError::SessionNotFound(_)) => (),
                Err(e) => return Err(e),
            }
        }
        if let Some(e164) = address.e164() {
            match self
                .delete_session(&ProtocolAddress::new(e164, device_id.into()))
                .await
            {
                Ok(()) => {
                    count += 1;
                },
                Err(SignalProtocolError::SessionNotFound(_)) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    // #[async_trait] sadly doesn't work here,
    // because calls to libsignal_protocol are unsend.
    fn compute_safety_number<'s>(
        &'s self,
        local_address: &'s ServiceAddress,
        address: &'s ServiceAddress,
        context: Context,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, SignalProtocolError>,
                > + 's,
        >,
    >
    where
        Self: Sized + libsignal_protocol::IdentityKeyStore,
    {
        Box::pin(async move {
            let addr = crate::cipher::get_preferred_protocol_address(
                self,
                address,
                DEFAULT_DEVICE_ID.into(),
            )
            .await?;
            let ident = self
                .get_identity(&addr, context)
                .await?
                .ok_or(SignalProtocolError::UntrustedIdentity(addr))?;
            let local = self
                .get_identity_key_pair(context)
                .await
                .expect("valid local identity");
            let fp = libsignal_protocol::Fingerprint::new(
                2,
                5200,
                local_address.e164_or_uuid().as_bytes(),
                local.identity_key(),
                address.e164_or_uuid().as_bytes(),
                &ident,
            )?;
            fp.display_string()
        })
    }
}
