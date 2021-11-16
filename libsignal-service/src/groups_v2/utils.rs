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

    let mut bytes = [0; GROUP_MASTER_KEY_LEN];
    hkdf::Hkdf::<sha2::Sha256>::new(None, group_id)
        .expand(b"GV2 Migration", &mut bytes)
        .expect("valid output length");
    Ok(GroupMasterKey::new(bytes))
}
