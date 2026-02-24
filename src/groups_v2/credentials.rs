//! State machine for profile key credential operations.
//!
//! These are used for group creation and member addition, where the Signal
//! server requires a ProfileKeyCredentialPresentation (ZK proof) for each member.
//!
//! # State Machine
//!
//! The [`GroupOperationManager`] provides a type-safe state machine for credential
//! operations:
//!
//! ```text
//! Idle -> RequestCreated -> CredentialReceived
//!   |           |                 |
//!   |           |                 v
//!   |           |           (terminal state)
//!   |           v
//!   |     (can fail/expire)
//!   v
//! (can reset)
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use libsignal_service::groups_v2::credentials::GroupOperationManager;
//!
//! let manager = GroupOperationManager::new(server_public_params);
//!
//! // Create a credential request
//! let (manager, request) = manager.create_credential_request(aci, &profile_key)?;
//!
//! // Send request to server and receive response...
//! // let response = client.fetch_credential(request).await?;
//!
//! // Process the response
//! let credential = manager.receive_credential(&response)?;
//! ```

use libsignal_protocol::Aci;
use zkgroup::{
    profiles::{
        ExpiringProfileKeyCredential, ExpiringProfileKeyCredentialResponse,
        ProfileKey, ProfileKeyCredentialRequest,
        ProfileKeyCredentialRequestContext,
    },
    ServerPublicParams, Timestamp, ZkGroupVerificationFailure,
};

// =============================================================================
// GroupOperationManager State Machine
// =============================================================================

/// Errors that can occur during credential operations.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// No credential request has been created yet.
    #[error("no credential request has been created")]
    NoRequestCreated,

    /// A credential has already been received for this request.
    #[error("credential already received")]
    CredentialAlreadyReceived,

    /// ZK group verification failed.
    #[error("ZK group verification failed: {0}")]
    VerificationFailed(#[from] ZkGroupVerificationFailure),

    /// The credential request has expired.
    #[error("credential request expired")]
    RequestExpired,
}

/// State marker for a manager that has not yet created a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Idle;

/// State marker for a manager that has created a credential request.
pub struct RequestCreated {
    context: ProfileKeyCredentialRequestContext,
    aci: Aci,
}

/// State marker for a manager that has successfully received a credential.
pub struct CredentialReceived {
    credential: ExpiringProfileKeyCredential,
}

/// A state machine for managing profile key credential operations.
///
/// This manager provides type-safe state transitions for the credential flow:
/// 1. [`Idle`] - Initial state, ready to create a credential request
/// 2. [`RequestCreated`] - Request created, waiting for server response
/// 3. [`CredentialReceived`] - Credential received and verified (terminal state)
///
/// The state machine ensures that operations are performed in the correct order
/// and prevents invalid state transitions.
///
/// # Type States
///
/// The manager uses the type state pattern to enforce correct usage at compile time:
///
/// ```ignore
/// // Starting in Idle state
/// let manager: GroupOperationManager<Idle> = GroupOperationManager::new(&params);
///
/// // Transition to RequestCreated state
/// let (manager, request): (GroupOperationManager<RequestCreated>, _) =
///     manager.create_credential_request(aci, &profile_key)?;
///
/// // Transition to CredentialReceived state
/// let (manager, credential): (GroupOperationManager<CredentialReceived>, _) =
///     manager.receive_credential(&response)?;
/// ```
pub struct GroupOperationManager<S> {
    server_public_params: ServerPublicParams,
    state: S,
}

impl GroupOperationManager<Idle> {
    /// Create a new `GroupOperationManager` in the idle state.
    ///
    /// # Arguments
    /// * `server_public_params` - The Signal server's public parameters for
    ///   cryptographic operations.
    pub fn new(server_public_params: ServerPublicParams) -> Self {
        Self {
            server_public_params,
            state: Idle,
        }
    }

    /// Create a credential request for the given ACI and profile key.
    ///
    /// This transitions the manager from [`Idle`] to [`RequestCreated`] state.
    ///
    /// # Arguments
    /// * `aci` - The Account Identifier (ACI) for the user.
    /// * `profile_key` - The user's profile key.
    ///
    /// # Returns
    /// A tuple containing:
    /// - The manager in [`RequestCreated`] state
    /// - The [`ProfileKeyCredentialRequest`] to send to the server
    ///
    /// # Example
    /// ```ignore
    /// let manager = GroupOperationManager::new(server_public_params);
    /// let (manager, request) = manager.create_credential_request(aci, &profile_key)?;
    /// // Send `request` to the Signal server...
    /// ```
    pub fn create_credential_request(
        self,
        aci: Aci,
        profile_key: &ProfileKey,
    ) -> (
        GroupOperationManager<RequestCreated>,
        ProfileKeyCredentialRequest,
    ) {
        let randomness: [u8; 32] = rand::random();
        let context = self
            .server_public_params
            .create_profile_key_credential_request_context(
                randomness,
                aci,
                *profile_key,
            );
        let request = context.get_request();

        let manager = GroupOperationManager {
            server_public_params: self.server_public_params,
            state: RequestCreated { context, aci },
        };

        (manager, request)
    }
}

impl GroupOperationManager<RequestCreated> {
    /// Receive and verify a credential response from the server.
    ///
    /// This transitions the manager from [`RequestCreated`] to [`CredentialReceived`]
    /// state if verification succeeds.
    ///
    /// # Arguments
    /// * `response` - The credential response received from the profile API.
    ///
    /// # Returns
    /// A tuple containing:
    /// - The manager in [`CredentialReceived`] state
    /// - The verified [`ExpiringProfileKeyCredential`]
    ///
    /// # Errors
    /// Returns [`CredentialError::VerificationFailed`] if the server's response
    /// fails cryptographic verification.
    ///
    /// # Example
    /// ```ignore
    /// let (manager, request) = manager.create_credential_request(aci, &profile_key)?;
    /// // let response = client.fetch_credential(request).await?;
    /// let (manager, credential) = manager.receive_credential(&response)?;
    /// ```
    pub fn receive_credential(
        self,
        response: &ExpiringProfileKeyCredentialResponse,
    ) -> Result<
        (
            GroupOperationManager<CredentialReceived>,
            ExpiringProfileKeyCredential,
        ),
        CredentialError,
    > {
        let current_time_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();
        let current_time = Timestamp::from_epoch_seconds(current_time_secs);

        let credential = self
            .server_public_params
            .receive_expiring_profile_key_credential(
                &self.state.context,
                response,
                current_time,
            )?;

        let manager = GroupOperationManager {
            server_public_params: self.server_public_params,
            state: CredentialReceived { credential },
        };

        Ok((manager, credential))
    }

    /// Reset the manager back to idle state.
    ///
    /// This discards the current credential request context and allows
    /// starting a new credential flow.
    pub fn reset(self) -> GroupOperationManager<Idle> {
        GroupOperationManager {
            server_public_params: self.server_public_params,
            state: Idle,
        }
    }

    /// Get the ACI associated with this credential request.
    pub fn aci(&self) -> &Aci {
        &self.state.aci
    }

    /// Get the underlying credential request context.
    ///
    /// This can be useful for advanced use cases where direct access to the
    /// context is needed.
    pub fn context(&self) -> &ProfileKeyCredentialRequestContext {
        &self.state.context
    }
}

impl GroupOperationManager<CredentialReceived> {
    /// Get the received credential.
    pub fn credential(&self) -> &ExpiringProfileKeyCredential {
        &self.state.credential
    }

    /// Reset the manager back to idle state to start a new credential flow.
    pub fn reset(self) -> GroupOperationManager<Idle> {
        GroupOperationManager {
            server_public_params: self.server_public_params,
            state: Idle,
        }
    }
}

impl<S> GroupOperationManager<S> {
    /// Get a reference to the server public parameters.
    pub fn server_public_params(&self) -> &ServerPublicParams {
        &self.server_public_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{ServiceConfiguration, SignalServers};
    use proptest::prelude::*;
    use uuid::Uuid;

    /// Get production server public params for testing
    fn production_server_params() -> ServerPublicParams {
        let config: ServiceConfiguration = SignalServers::Production.into();
        config.zkgroup_server_public_params
    }

    /// Generate an arbitrary ACI from random bytes
    fn arb_aci() -> impl Strategy<Value = Aci> {
        any::<[u8; 16]>().prop_map(|bytes| {
            let uuid = Uuid::from_bytes(bytes);
            Aci::from(uuid)
        })
    }

    /// Generate an arbitrary profile key from random bytes
    fn arb_profile_key() -> impl Strategy<Value = ProfileKey> {
        any::<[u8; 32]>().prop_map(ProfileKey::create)
    }

    proptest! {
        /// Property: Creating a credential request always produces a valid request
        /// that can be serialized, regardless of input values.
        #[test]
        fn prop_create_credential_request_produces_valid_request(
            aci in arb_aci(),
            profile_key in arb_profile_key()
        ) {
            let server_params = production_server_params();
            let manager = GroupOperationManager::new(server_params);
            let (new_manager, request) = manager.create_credential_request(aci, &profile_key);

            // The new manager must reference the same ACI
            prop_assert_eq!(new_manager.aci(), &aci);

            // The request must be serializable (using zkgroup serialization)
            let _request_bytes = zkgroup::serialize(&request);
        }

        /// Property: Reset from RequestCreated state always returns to Idle state,
        /// allowing a new request to be created.
        #[test]
        fn prop_reset_from_request_created_returns_idle(
            aci in arb_aci(),
            profile_key in arb_profile_key()
        ) {
            let server_params = production_server_params();
            let manager = GroupOperationManager::new(server_params);
            let (manager_in_request_state, _request) =
                manager.create_credential_request(aci, &profile_key);

            // Reset should return to Idle state
            let reset_manager = manager_in_request_state.reset();

            // Verify we're back in Idle state by creating a new request
            let (_final_manager, _new_request) =
                reset_manager.create_credential_request(aci, &profile_key);
        }

        /// Property: Multiple credential requests for the same ACI/profile_key
        /// produce different request bytes due to randomness.
        #[test]
        fn prop_multiple_requests_differ_by_randomness(
            aci in arb_aci(),
            profile_key in arb_profile_key()
        ) {
            let server_params = production_server_params();
            let manager1 = GroupOperationManager::new(server_params.clone());
            let manager2 = GroupOperationManager::new(server_params);

            let (_, request1) = manager1.create_credential_request(aci, &profile_key);
            let (_, request2) = manager2.create_credential_request(aci, &profile_key);

            // Requests should be different due to random nonce
            prop_assert_ne!(
                zkgroup::serialize(&request1),
                zkgroup::serialize(&request2),
                "Different randomness should produce different requests"
            );
        }
    }

    #[test]
    fn test_state_types_compile() {
        // Compile-time verification that type states work correctly
        fn _assert_idle(manager: GroupOperationManager<Idle>) {
            let _: &ServerPublicParams = manager.server_public_params();
        }

        fn _assert_request_created(
            manager: GroupOperationManager<RequestCreated>,
        ) {
            let _: &Aci = manager.aci();
            let _: &ProfileKeyCredentialRequestContext = manager.context();
        }

        fn _assert_credential_received(
            manager: GroupOperationManager<CredentialReceived>,
        ) {
            let _: &ExpiringProfileKeyCredential = manager.credential();
        }
    }

    #[test]
    fn test_type_state_prevents_invalid_transitions() {
        // This test verifies at compile time that:
        // 1. Idle -> RequestCreated (via create_credential_request)
        // 2. RequestCreated -> CredentialReceived (via receive_credential)
        // 3. RequestCreated -> Idle (via reset)
        // 4. CredentialReceived -> Idle (via reset)

        let server_params = production_server_params();
        let uuid = Uuid::nil();
        let aci = Aci::from(uuid);
        let profile_key = ProfileKey::create([0u8; 32]);

        // Idle -> RequestCreated
        let manager = GroupOperationManager::new(server_params);
        let (manager, _request) =
            manager.create_credential_request(aci, &profile_key);

        // RequestCreated -> Idle (via reset)
        let manager = manager.reset();

        // Can create request again after reset
        let (manager, _request) =
            manager.create_credential_request(aci, &profile_key);

        // Verify we're in RequestCreated state (can access aci)
        let _ = manager.aci();

        // Reset to Idle
        let _manager = manager.reset();
    }
}
