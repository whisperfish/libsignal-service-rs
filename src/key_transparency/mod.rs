//! Key Transparency module for Signal service.
//!
//! Provides WebSocket transport for Signal's Key Transparency system
//! and a state-storage trait for persisting KT verification data.
//!
//! Enable with the `key-transparency` feature flag.

pub mod store;
pub mod websocket;

pub use store::{
    InMemoryKeyTransparencyStore, KeyTransparencyStore, LastTreeHead,
};
pub use websocket::{KeyTransparencyWebSocketError, ValueMonitor};

// Re-export core KT types that consumers will need alongside our wrappers.
pub use libsignal_keytrans::{MonitoringData, TreeHead, TreeRoot};

use crate::utils::TryIntoE164;
use crate::websocket::SignalWebSocket;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::PublicConfig;
use libsignal_protocol::PublicKey;
use usernames::Username;
use zkgroup::profiles::ProfileKey;

// ---------------------------------------------------------------------------
// ChatSearchParams – search parameters for KT requests
// ---------------------------------------------------------------------------

/// Full parameter set for a Key Transparency search request.
///
/// Bundles all inputs required to perform a search operation against the
/// Signal Key Transparency log. All fields describe the **target** user
/// (the one being searched for), not the searching user.
#[derive(Debug)]
pub struct ChatSearchParams<P = E164> {
    /// The target user's ACI (always required).
    pub target_aci: Aci,
    /// The target user's identity key.
    pub target_identity_key: PublicKey,
    /// Optional target phone number for cross-verification.
    pub target_e164: Option<P>,
    /// Optional target username for cross-verification.
    pub target_username: Option<Username>,
    /// Optional profile key used to derive the unidentified access key.
    pub target_profile_key: Option<ProfileKey>,
    /// Optional last tree head size for incremental verification.
    pub last_tree_head_size: Option<u64>,
    /// Optional distinguished tree head size for incremental verification.
    pub distinguished_tree_head_size: Option<u64>,
}

// ---------------------------------------------------------------------------
// Public Config Constructors
// ---------------------------------------------------------------------------

/// Returns a PublicConfig for the production Key Transparency deployment.
///
/// Uses hardcoded keys from libsignal-net v0.91.0.
pub fn production_public_config() -> PublicConfig {
    use libsignal_keytrans::DeploymentMode;
    use libsignal_keytrans::VerifyingKey;
    use libsignal_keytrans::VerifyingKeys;
    use libsignal_keytrans::VrfPublicKey;

    let signature_key = VerifyingKey::from_bytes(
        &hex::decode(
            "a3973067984382cfa89ec26d7cc176680aefe92b3d2eba85159dad0b8354b622",
        )
        .unwrap()
        .try_into()
        .expect("32 bytes"),
    )
    .expect("valid production signature key");

    let vrf_key_bytes: [u8; 32] = hex::decode(
        "3849cf116c7bc9aef5f13f0c61a7c246e5bade4eb7e1c7b0efcacdd8c1e6a6ff",
    )
    .unwrap()
    .try_into()
    .expect("32 bytes");
    let vrf_key = VrfPublicKey::try_from(vrf_key_bytes)
        .expect("valid production VRF key");

    let auditor_keys = VerifyingKeys::from([
        VerifyingKey::from_bytes(
            &hex::decode("2d973608e909a09e12cbdbd21ad58775fd72fe1034a5a079f26541d5764ce17f")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 1"),
        VerifyingKey::from_bytes(
            &hex::decode("2f217a86cd2dbc95d46a84420942a95877b3723f634bc64bb9e406796df746ef")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 2"),
        VerifyingKey::from_bytes(
            &hex::decode("7fe5d91de235188486d8fb836a6da37e625e2b10eb6d144185b9364cc83cbbb6")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 3"),
    ]);

    PublicConfig {
        mode: DeploymentMode::ThirdPartyAuditing(auditor_keys),
        signature_key,
        vrf_key,
    }
}

/// Returns a PublicConfig for the staging Key Transparency deployment.
///
/// Uses hardcoded keys from libsignal-net v0.91.0.
pub fn staging_public_config() -> PublicConfig {
    use libsignal_keytrans::DeploymentMode;
    use libsignal_keytrans::VerifyingKey;
    use libsignal_keytrans::VerifyingKeys;
    use libsignal_keytrans::VrfPublicKey;

    let signature_key = VerifyingKey::from_bytes(
        &hex::decode(
            "ac0de1fd7f33552bbeb6ebc12b9d4ea10bf5f025c45073d3fb5f5648955a749e",
        )
        .unwrap()
        .try_into()
        .expect("32 bytes"),
    )
    .expect("valid staging signature key");

    let vrf_key_bytes: [u8; 32] = hex::decode(
        "ec3a268237cf5c47115cf222405d5f90cc633ebe05caf82c0dd5acf9d341dadb",
    )
    .unwrap()
    .try_into()
    .expect("32 bytes");
    let vrf_key =
        VrfPublicKey::try_from(vrf_key_bytes).expect("valid staging VRF key");

    let auditor_keys = VerifyingKeys::from([
        VerifyingKey::from_bytes(
            &hex::decode("1123b13ee32479ae6af5739e5d687b51559abf7684120511f68cde7a21a0e755")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 1"),
        VerifyingKey::from_bytes(
            &hex::decode("bd1e26a0fbdbfa923486ccc9296f4227db490b4add29f5507775171ea0fb7a4e")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 2"),
        VerifyingKey::from_bytes(
            &hex::decode("093ee42d95502b3e81f4e604179c82c149fffb96167642b9eb81b03d6e2dd636")
                .unwrap()
                .try_into()
                .expect("32 bytes"),
        )
        .expect("valid auditor key 3"),
    ]);

    PublicConfig {
        mode: DeploymentMode::ThirdPartyAuditing(auditor_keys),
        signature_key,
        vrf_key,
    }
}

// ---------------------------------------------------------------------------
// Error type – placeholder until error.rs is created
// ---------------------------------------------------------------------------

/// Errors that can occur during Key Transparency operations.
///
/// TODO: Replace with the full error enum from `error.rs` once that module is
/// implemented (see plan task 2).
#[derive(Debug, thiserror::Error)]
pub enum KeyTransparencyError {
    /// Verification of a proof failed.
    #[error("KT verification failed: {0}")]
    VerificationFailed(String),
    /// Store error (I/O, serialization).
    #[error("KT store error: {0}")]
    Store(String),
    /// The requested identifier has no monitoring data.
    /// Call `search_and_verify` first to start monitoring.
    #[error("no monitoring data; search first")]
    NotMonitored,
    /// The tree head is inconsistent with a previously stored one.
    #[error("KT tree head inconsistency detected")]
    TreeHeadInconsistency,
    /// Transport error (e.g. network failure, server error).
    #[error("KT transport error: {0}")]
    Transport(String),
}

impl From<libsignal_keytrans::Error> for KeyTransparencyError {
    fn from(e: libsignal_keytrans::Error) -> Self {
        Self::VerificationFailed(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Outcome of a verified search operation.
#[derive(Debug, Clone)]
pub struct VerifiedSearchResult {
    /// The ACI that was searched.
    pub aci: libsignal_core::Aci,
    /// Whether the identity key was found in the transparency log.
    pub key_matches: bool,
    /// Whether the search also started monitoring this contact.
    pub now_monitored: bool,
}

/// Outcome of a verified monitor operation.
#[derive(Debug, Clone)]
pub struct VerifiedMonitorResult {
    /// Whether the monitored contact's key has changed since last check.
    pub key_changed: bool,
    /// The new identity key, if a change was detected.
    pub new_key: Option<libsignal_protocol::PublicKey>,
}

// ---------------------------------------------------------------------------
// KeyTransparencyClient
// ---------------------------------------------------------------------------

use libsignal_keytrans::{
    FullSearchResponse, MonitorContext, MonitorKey, MonitorRequest,
    SearchContext, SlimSearchRequest,
};

/// High-level Key Transparency client.
///
/// Wraps `libsignal_keytrans` verification logic with storage management.
/// Consumers use this to verify identity keys against Signal's transparency
/// log and persist verified state.
///
/// This struct provides verification-only methods. For transport integration
/// (fetching responses from the KT server via WebSocket), see the
/// transport-aware methods.
///
/// # Type parameters
///
/// * `S` – A [`KeyTransparencyStore`] implementation that persists tree
///   heads and monitoring data (e.g. `InMemoryKeyTransparencyStore` for
///   testing, or a SQLite-backed store in Whisperfish).
pub struct KeyTransparencyClient<'a, S: KeyTransparencyStore> {
    /// The libsignal KT verification engine.
    inner: libsignal_keytrans::KeyTransparency,
    /// Persistent KT state.
    store: &'a S,
    /// WebSocket connection for KT server communication.
    socket: &'a mut SignalWebSocket<crate::websocket::Identified>,
}

impl<'a, S: KeyTransparencyStore> KeyTransparencyClient<'a, S> {
    /// Create a new KT client with the given configuration, storage backend, and websocket.
    pub fn new(
        config: PublicConfig,
        store: &'a S,
        socket: &'a mut SignalWebSocket<crate::websocket::Identified>,
    ) -> Self {
        let inner = libsignal_keytrans::KeyTransparency { config };
        Self {
            inner,
            store,
            socket,
        }
    }

    /// Clear all stored KT state.
    pub async fn clear(&self) -> Result<(), KeyTransparencyError> {
        self.store.clear().await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transport-aware methods
// ---------------------------------------------------------------------------

/// Transport methods require the `key-transparency` feature.
#[cfg(feature = "key-transparency")]
impl<'a, S: KeyTransparencyStore> KeyTransparencyClient<'a, S> {
    /// Search for a contact's identity key in the KT log,
    /// fetch the response from the server, and verify it.
    ///
    /// Combines transport + verification in one call.
    /// This is the most convenient entry point for consumers.
    pub async fn search_and_verify<P>(
        &mut self,
        params: ChatSearchParams<P>,
    ) -> Result<VerifiedSearchResult, KeyTransparencyError>
    where
        P: TryIntoE164,
    {
        let _response = self
            .socket
            .key_transparency_search(params)
            .await
            .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;
        // TODO: slim request from response, call self.verify_search()
        todo!()
    }

    /// Monitor a previously-searched contact for key changes.
    pub async fn monitor_and_verify(
        &mut self,
        aci: libsignal_core::Aci,
    ) -> Result<VerifiedMonitorResult, KeyTransparencyError> {
        // TODO:
        // 1. Build MonitorRequest from stored monitoring data
        // 2. Send via socket
        // 3. Call self.verify_monitor()
        let _ = aci;
        let _request = MonitorRequest::default();
        let _response =
            self.socket
                .key_transparency_monitor(&_request)
                .await
                .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;
        todo!()
    }

    /// Fetch and verify the distinguished tree head.
    pub async fn check_distinguished(
        &mut self,
    ) -> Result<TreeRoot, KeyTransparencyError> {
        let _response = self
            .socket
            .key_transparency_distinguished(None)
            .await
            .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;
        // TODO: call self.verify_distinguished()
        todo!()
    }
}
