use libsignal_protocol::error::SignalProtocolError;
use zkgroup::groups::GroupMasterKey;
use zkgroup::GROUP_MASTER_KEY_LEN;

/// Given a 16-byte GroupV1 ID, derive the migration key.
///
/// Panics if the group_id is not 16 bytes long.
pub fn derive_v2_migration_master_key(
    group_id: &[u8],
) -> Result<GroupMasterKey, SignalProtocolError> {
    assert_eq!(group_id.len(), 16, "Group ID must be exactly 16 bytes");
    let hkdf = libsignal_protocol::HKDF::new(3)?;
    let bytes =
        hkdf.derive_secrets(group_id, b"GV2 Migration", GROUP_MASTER_KEY_LEN)?;
    let mut bytes_stack = [0u8; GROUP_MASTER_KEY_LEN];
    bytes_stack.copy_from_slice(&bytes);
    Ok(GroupMasterKey::new(bytes_stack))
}
