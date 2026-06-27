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
use crate::websocket::{SignalWebSocket, Unidentified};
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

/// Returns a `PublicConfig` for the production Key Transparency deployment.
///
/// Mirrors the key material in `libsignal_net::env::PROD.keytrans_config`
/// (rust/net/src/env.rs, consts `KEYTRANS_*_PROD`). Hardcoded rather than sourced
/// from `libsignal-net` so the `key-transparency` feature does not pull in the
/// `cdsi` transport; re-check these on libsignal bumps.
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

/// Returns a `PublicConfig` for the staging Key Transparency deployment.
///
/// Mirrors `libsignal_net::env::STAGING.keytrans_config`; see
/// [`production_public_config`] for why these are hardcoded.
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
///
/// Monitor proves that a previously-searched entry is still correctly placed
/// in a consistently-grown tree; it does not surface value changes (that
/// requires re-searching). Mirrors `libsignal-net`'s `monitor()`, which returns
/// updated `AccountData` rather than a change flag.
#[derive(Debug, Clone)]
pub struct VerifiedMonitorResult {
    /// Whether the monitor proof verified against the current tree head.
    pub verified: bool,
    /// Root hash of the tree head the monitor proof was checked against.
    pub tree_root: TreeRoot,
}

// ---------------------------------------------------------------------------
// KeyTransparencyClient
// ---------------------------------------------------------------------------

use libsignal_core::ServiceId;
use libsignal_keytrans::{
    FullSearchResponse, MonitorContext, MonitorKey, MonitorRequest,
    SearchContext, SlimSearchRequest,
};
use std::collections::HashMap;
use std::time::SystemTime;

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
    socket: &'a mut SignalWebSocket<Unidentified>,
}

impl<'a, S: KeyTransparencyStore> KeyTransparencyClient<'a, S> {
    /// Create a new KT client with the given configuration, storage backend, and websocket.
    pub fn new(
        config: PublicConfig,
        store: &'a S,
        socket: &'a mut SignalWebSocket<Unidentified>,
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
    /// Search for a contact's identity key in the KT log, fetch the response
    /// from the server, and verify it.
    ///
    /// Refreshes the distinguished tree head (anchoring consistency), issues
    /// the search, cryptographically verifies the ACI entry, and persists the
    /// resulting monitoring data. `key_matches` is whether the committed value
    /// equals `params.target_identity_key`.
    pub async fn search_and_verify<P>(
        &mut self,
        params: ChatSearchParams<P>,
    ) -> Result<VerifiedSearchResult, KeyTransparencyError>
    where
        P: TryIntoE164,
    {
        // Anchoring distinguished head first: the search request's
        // `distinguishedTreeHeadSize` must be a real, verified size.
        self.check_distinguished().await?;
        let distinguished = self
            .store
            .get_last_distinguished_tree_head()
            .await
            .expect("check_distinguished persists a head");
        let distinguished_size = distinguished.tree_head.tree_size;
        let last_distinguished = libsignal_keytrans::LastTreeHead(
            distinguished.tree_head,
            distinguished.root,
        );

        // Capture what we need for verification before `params` moves into
        // the transport call.
        let target_aci = params.target_aci;
        let expected_value = params.target_identity_key.serialize();
        let search_key = [
            b"a",
            ServiceId::from(target_aci).service_id_binary().as_slice(),
        ]
        .concat();

        // Seed incremental params from the store when the caller didn't.
        let mut params = params;
        params.distinguished_tree_head_size = Some(distinguished_size);
        if params.last_tree_head_size.is_none() {
            params.last_tree_head_size = self
                .store
                .get_last_tree_head()
                .await
                .map(|h| h.tree_head.tree_size);
        }

        let response = self
            .socket
            .key_transparency_search(params)
            .await
            .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;

        let tree_head = response.tree_head.ok_or_else(|| {
            KeyTransparencyError::VerificationFailed(
                "search response without tree head".into(),
            )
        })?;
        let aci = response.aci.ok_or_else(|| {
            KeyTransparencyError::VerificationFailed(
                "search response without ACI entry".into(),
            )
        })?;

        let last_tree_head = self
            .store
            .get_last_tree_head()
            .await
            .map(|h| libsignal_keytrans::LastTreeHead(h.tree_head, h.root));
        let monitoring = self.store.get_monitoring_data(&search_key).await;

        let search_response = FullSearchResponse::new(aci, &tree_head);
        let context = SearchContext {
            last_tree_head: last_tree_head.as_ref(),
            last_distinguished_tree_head: Some(&last_distinguished),
            data: monitoring,
        };
        let result = self.inner.verify_search(
            SlimSearchRequest {
                search_key: search_key.clone(),
                version: None,
            },
            search_response,
            context,
            // Always start monitoring on search; `false` is only used for the
            // distinguished key (which isn't monitored). Mirrors
            // libsignal-net's `verify_single_search_response`
            // (rust/net/chat/src/api/keytrans/verify_ext.rs).
            true,
            SystemTime::now(),
        )?;

        // Persist the updated state.
        if let Some(md) = &result.state_update.monitoring_data {
            self.store
                .set_monitoring_data(&search_key, md.clone())
                .await;
        }
        self.store
            .set_last_tree_head(
                result.state_update.tree_head.clone(),
                result.state_update.tree_root,
            )
            .await;

        // Constant-time compare would be ideal; for the example a plain eq
        // suffices. Upstream uses SearchValue::check_equal.
        // The committed value is version-prefixed (0x00 + serialized
        // identity key); strip the version byte before comparing, mirroring
        // libsignal-net's SearchValue::check_equal.
        let key_matches = result
            .value
            .split_first()
            .filter(|(version, _)| **version == 0)
            .map(|(_, rest)| rest == expected_value.as_ref())
            .unwrap_or(false);

        Ok(VerifiedSearchResult {
            aci: target_aci,
            key_matches,
            now_monitored: result.state_update.monitoring_data.is_some(),
        })
    }

    /// Monitor a previously-searched contact for consistency.
    ///
    /// After [`search_and_verify`] establishes a contact's position in the
    /// log, monitor proves — cheaply, via path proofs rather than a fresh
    /// binary search — that the entry is still correctly placed in a
    /// consistently-grown tree. Loads stored `MonitoringData` for the ACI's
    /// search key, refreshes the distinguished head, builds a `MonitorRequest`
    /// (with `entry_position`/`commitment_index` from the stored data and
    /// `consistency` sizes from the store), POSTs, and verifies.
    ///
    /// Mirrors `libsignal-net`'s `monitor()`
    /// (rust/net/chat/src/api/keytrans.rs); the public `verify_monitor` skips
    /// upstream's `try_from_untyped` conversion, which the transport already
    /// does on the `ChatMonitorResponse` bytes.
    pub async fn monitor_and_verify(
        &mut self,
        aci: libsignal_core::Aci,
    ) -> Result<VerifiedMonitorResult, KeyTransparencyError> {
        let search_key =
            [b"a", ServiceId::from(aci).service_id_binary().as_slice()]
                .concat();
        let monitoring = self
            .store
            .get_monitoring_data(&search_key)
            .await
            .ok_or(KeyTransparencyError::NotMonitored)?;
        // Refresh the distinguished head first and read it back: it anchors
        // consistency and seeds `lastDistinguishedTreeHeadSize`.
        self.check_distinguished().await?;
        let distinguished = self
            .store
            .get_last_distinguished_tree_head()
            .await
            .expect("check_distinguished persists a head");
        let last_distinguished = libsignal_keytrans::LastTreeHead(
            distinguished.tree_head.clone(),
            distinguished.root,
        );

        // Sourced from the store per upstream (rust/net/chat/src/ws/keytrans.rs
        // takes these directly, not from the proto `Consistency`). `verify_monitor`
        // uses a `Consistency`-less request.
        let last_tree_head_size = self
            .store
            .get_last_tree_head()
            .await
            .map(|h| h.tree_head.tree_size);
        let distinguished_size = self
            .store
            .get_last_distinguished_tree_head()
            .await
            .map(|h| h.tree_head.tree_size);

        let request = MonitorRequest {
            keys: vec![MonitorKey {
                search_key: search_key.clone(),
                entry_position: monitoring.latest_log_position(),
                commitment_index: monitoring.index.to_vec(),
            }],
            consistency: None,
        };

        let response = self
            .socket
            .key_transparency_monitor(
                &request,
                last_tree_head_size,
                distinguished_size,
            )
            .await
            .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;

        if response.tree_head.is_none() {
            return Err(KeyTransparencyError::VerificationFailed(
                "monitor response without tree head".into(),
            ));
        }
        let last_tree = self
            .store
            .get_last_tree_head()
            .await
            .map(|h| libsignal_keytrans::LastTreeHead(h.tree_head, h.root));
        let mut data_map = HashMap::new();
        data_map.insert(search_key.clone(), monitoring);
        let context = MonitorContext {
            last_tree_head: last_tree.as_ref(),
            last_distinguished_tree_head: &last_distinguished,
            data: data_map,
        };
        let mut verified = self.inner.verify_monitor(
            &request,
            &response,
            context,
            SystemTime::now(),
        )?;

        // Persist the updated monitoring data + tree head.
        if let Some(md) = verified.monitoring_data.remove(&search_key) {
            self.store.set_monitoring_data(&search_key, md).await;
        }
        self.store
            .set_last_tree_head(verified.tree_head.clone(), verified.tree_root)
            .await;
        // The distinguished head is the same root; keep it fresh too.
        self.store
            .set_last_distinguished_tree_head(
                verified.tree_head,
                verified.tree_root,
            )
            .await;

        Ok(VerifiedMonitorResult {
            verified: true,
            tree_root: verified.tree_root,
        })
    }

    /// Fetch and verify the distinguished tree head.
    ///
    /// Refreshes (and persists) the store's distinguished tree head and returns
    /// its root hash. Mirrors `libsignal-net`'s `distinguished()`, which drives
    /// the public `verify_search` with `SlimSearchRequest::new(b"distinguished")`.
    pub async fn check_distinguished(
        &mut self,
    ) -> Result<TreeRoot, KeyTransparencyError> {
        let last_distinguished =
            self.store.get_last_distinguished_tree_head().await;
        let last_for_context = last_distinguished.as_ref().map(|h| {
            libsignal_keytrans::LastTreeHead(h.tree_head.clone(), h.root)
        });
        let last_tree_head_size =
            last_distinguished.as_ref().map(|h| h.tree_head.tree_size);

        let response = self
            .socket
            .key_transparency_distinguished(last_tree_head_size)
            .await
            .map_err(|e| KeyTransparencyError::Transport(e.to_string()))?;

        let tree_head = response.tree_head.ok_or_else(|| {
            KeyTransparencyError::VerificationFailed(
                "distinguished response without tree head".into(),
            )
        })?;
        let distinguished = response.distinguished.ok_or_else(|| {
            KeyTransparencyError::VerificationFailed(
                "distinguished response without distinguished entry".into(),
            )
        })?;

        let search_response =
            FullSearchResponse::new(distinguished, &tree_head);
        let context = SearchContext {
            last_tree_head: None,
            last_distinguished_tree_head: last_for_context.as_ref(),
            data: None,
        };
        let result = self.inner.verify_search(
            SlimSearchRequest {
                search_key: b"distinguished".to_vec(),
                version: None,
            },
            search_response,
            context,
            false,
            SystemTime::now(),
        )?;

        let root = result.state_update.tree_root;
        self.store
            .set_last_distinguished_tree_head(
                result.state_update.tree_head,
                root,
            )
            .await;
        Ok(root)
    }
}
