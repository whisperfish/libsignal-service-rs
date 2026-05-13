//! Key Transparency state storage.
//!
//! Defines the [`KeyTransparencyStore`] trait for persisting Key Transparency
//! client state (tree heads and per-identifier monitoring data). An in-memory
//! implementation is provided for testing.

use async_trait::async_trait;
use libsignal_keytrans::{MonitoringData, TreeRoot};

/// Persistent state for Key Transparency verification.
///
/// Implementors store the last verified tree head and per-identifier monitoring
/// data so that the KT client can verify consistency across sessions.
///
/// Whisperfish would typically implement this trait over SQLite; an in-memory
/// implementation is provided here for testing.
#[async_trait]
pub trait KeyTransparencyStore: Send + Sync {
    /// Return the last tree head that was successfully verified, together with
    /// its root hash.
    async fn get_last_tree_head(&self) -> Option<LastTreeHead>;

    /// Persist the most recently verified tree head and its root hash.
    async fn set_last_tree_head(&self, head: TreeHead, root: TreeRoot);

    /// Return the monitoring data for an identifier key (e.g. an ACI as raw
    /// bytes). Returns `None` if the identifier is not being tracked.
    async fn get_monitoring_data(&self, key: &[u8]) -> Option<MonitoringData>;

    /// Persist monitoring data for an identifier key.
    async fn set_monitoring_data(&self, key: &[u8], data: MonitoringData);

    /// Remove all stored KT state. Useful for debugging or resetting a
    /// corrupted local state.
    async fn clear(&self);
}

/// A verified tree head paired with its root hash.
///
/// Thin wrapper around [`libsignal_keytrans::LastTreeHead`] that owns its
/// data, making it suitable for storage.
#[derive(Debug, Clone, PartialEq)]
pub struct LastTreeHead {
    /// The tree head (tree size, timestamp, auditor signatures).
    pub tree_head: TreeHead,
    /// 32-byte root hash of the Merkle tree.
    pub root: TreeRoot,
}

// Re-export TreeHead from libsignal_keytrans so consumers don't need to
// depend on it directly just for the type.
pub use libsignal_keytrans::TreeHead;

// ---------------------------------------------------------------------------
// In-memory implementation (for testing)
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory [`KeyTransparencyStore`] suitable for tests.
pub struct InMemoryKeyTransparencyStore {
    last_tree_head: Mutex<Option<LastTreeHead>>,
    monitoring_data: Mutex<HashMap<Vec<u8>, MonitoringData>>,
}

impl InMemoryKeyTransparencyStore {
    pub fn new() -> Self {
        Self {
            last_tree_head: Mutex::new(None),
            monitoring_data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryKeyTransparencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyTransparencyStore for InMemoryKeyTransparencyStore {
    async fn get_last_tree_head(&self) -> Option<LastTreeHead> {
        self.last_tree_head
            .lock()
            .expect("last_tree_head lock")
            .clone()
    }

    async fn set_last_tree_head(&self, head: TreeHead, root: TreeRoot) {
        *self.last_tree_head.lock().expect("last_tree_head lock") =
            Some(LastTreeHead {
                tree_head: head,
                root,
            });
    }

    async fn get_monitoring_data(&self, key: &[u8]) -> Option<MonitoringData> {
        self.monitoring_data
            .lock()
            .expect("monitoring_data lock")
            .get(key)
            .cloned()
    }

    async fn set_monitoring_data(&self, key: &[u8], data: MonitoringData) {
        self.monitoring_data
            .lock()
            .expect("monitoring_data lock")
            .insert(key.to_vec(), data);
    }

    async fn clear(&self) {
        *self.last_tree_head.lock().expect("last_tree_head lock") = None;
        self.monitoring_data
            .lock()
            .expect("monitoring_data lock")
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_store_round_trip() {
        let store = InMemoryKeyTransparencyStore::new();

        assert!(store.get_last_tree_head().await.is_none());

        let root: TreeRoot = [42u8; 32];
        let head = TreeHead {
            tree_size: 1234_u64,
            timestamp: 1_700_000_000_i64,
            signatures: vec![],
        };
        store.set_last_tree_head(head.clone(), root).await;

        let stored = store.get_last_tree_head().await.unwrap();
        assert_eq!(stored.tree_head.tree_size, 1234);
        assert_eq!(stored.root, root);

        // Monitoring data round-trip
        let key = b"some-aci-uuid";
        let data = MonitoringData {
            index: [1u8; 32],
            pos: 100,
            ptrs: HashMap::new(),
            owned: false,
            search_key: vec![1, 2, 3],
        };
        store.set_monitoring_data(key, data.clone()).await;

        let stored_data = store.get_monitoring_data(key).await.unwrap();
        assert_eq!(stored_data.pos, 100);
        assert_eq!(stored_data.search_key, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_in_memory_store_clear() {
        let store = InMemoryKeyTransparencyStore::new();

        let root: TreeRoot = [0u8; 32];
        let head = TreeHead {
            tree_size: 1_u64,
            timestamp: 0_i64,
            signatures: vec![],
        };
        store.set_last_tree_head(head, root).await;
        store
            .set_monitoring_data(
                b"key",
                MonitoringData {
                    index: [0u8; 32],
                    pos: 0,
                    ptrs: HashMap::new(),
                    owned: false,
                    search_key: vec![],
                },
            )
            .await;

        store.clear().await;
        assert!(store.get_last_tree_head().await.is_none());
        assert!(store.get_monitoring_data(b"key").await.is_none());
    }
}
