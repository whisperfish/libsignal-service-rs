use libsignal_protocol::error::SignalProtocolError;
use uuid::Uuid;
use zkgroup::groups::GroupMasterKey;
use zkgroup::GROUP_MASTER_KEY_LEN;

/// Given a 16-byte GroupV1 ID, derive the migration key.
///
/// Panics if the group_id is not 16 bytes long.
pub fn derive_v2_migration_master_key(
    group_id: &[u8],
) -> Result<GroupMasterKey, SignalProtocolError> {
    assert_eq!(group_id.len(), 16, "Group ID must be exactly 16 bytes");

    let mut bytes = [0; GROUP_MASTER_KEY_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, group_id)
        .expand(b"GV2 Migration", &mut bytes)
        .expect("valid output length");
    Ok(GroupMasterKey::new(bytes))
}

/// Derive a DistributionId from a GroupMasterKey.
///
/// The DistributionId is used to identify the sender key for a group.
/// All members of the group will derive the same DistributionId from the
/// shared GroupMasterKey, allowing them to use the same sender key.
///
/// # Arguments
///
/// * `master_key_bytes` - The group's master key bytes (32 bytes)
///
/// # Returns
///
/// A UUID derived from the master key using HKDF-SHA256.
///
/// # Panics
///
/// Panics if `master_key_bytes` is not exactly 32 bytes.
pub fn derive_distribution_id(master_key_bytes: &[u8]) -> Uuid {
    assert_eq!(
        master_key_bytes.len(),
        GROUP_MASTER_KEY_LEN,
        "master key must be exactly 32 bytes"
    );

    // Derive a 16-byte identifier from the master key
    let mut distribution_id_bytes = [0u8; 16];
    hkdf::Hkdf::<sha2::Sha256>::new(None, master_key_bytes)
        .expand(b"SenderKey DistributionId", &mut distribution_id_bytes)
        .expect("valid output length");

    // Create a UUID from the derived bytes
    // Using UUID v4 format (random) since this is a derived identifier
    Uuid::from_bytes(distribution_id_bytes)
}
