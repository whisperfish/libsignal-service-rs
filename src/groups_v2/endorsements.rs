//! Group Send Endorsements support.
//!
//! Group Send Endorsements allow anonymous sending to group members without
//! per-member access keys. The server issues endorsements that can be combined
//! or subtracted to efficiently authorize sends to any subset of group members.
//!
//! # Overview
//!
//! When a group is fetched or modified, the server returns a `groupSendEndorsementsResponse`
//! containing endorsements for all group members. These are decoded using the group's
//! secret parameters and stored locally.
//!
//! When sending a message to a group:
//! 1. Build a `GroupSendTokenBuilder` from stored endorsements
//! 2. Call `build_token_for_members()` with the recipient set
//! 3. Use the resulting `GroupSendToken` in the `Group-Send-Token` HTTP header
//!
//! # Example
//!
//! ```ignore
//! let endorsements = decode_group_send_endorsements_response(
//!     response_bytes,
//!     group_id,
//!     &group_secret_params,
//!     &server_public_params,
//!     &members,
//!     now,
//! )?;
//!
//! let builder = GroupSendTokenBuilder::new(
//!     endorsements.combined_endorsement,
//!     endorsements.member_endorsements,
//!     group_secret_params,
//!     local_aci,
//! );
//!
//! builder.validate_expiration(now)?;
//! let token = builder.build_token_for_members(&recipients)?;
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use libsignal_core::ServiceId;
use libsignal_protocol::Aci;
use zkgroup::{
    api::groups::{GroupSendEndorsement, GroupSendEndorsementsResponse},
    groups::GroupSecretParams,
    Timestamp, ZkGroupDeserializationFailure, ZkGroupVerificationFailure,
};

use crate::sender::GroupV2Id;

// Re-export for convenience
#[allow(unused_imports)]
pub use zkgroup::api::groups::GroupSendFullToken;
/// Opaque token for sending to a group or subset of members.
///
/// This wraps the serialized form suitable for HTTP headers.
/// Create via `GroupSendTokenBuilder`.
#[derive(Clone, Debug)]
pub struct GroupSendToken(Vec<u8>);

impl GroupSendToken {
    /// Create from serialized bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get base64-encoded form for HTTP header.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.0)
    }
}

/// Stored combined endorsement for a group.
///
/// This endorsement covers all group members and can be used to efficiently
/// build tokens for the entire group or large subsets via subtraction.
#[derive(Clone, Debug)]
pub struct GroupSendCombinedEndorsement {
    /// The group this endorsement is for.
    pub group_id: GroupV2Id,
    /// Expiration as Unix timestamp in seconds.
    pub expiration: u64,
    /// The serialized endorsement (compressed form for storage).
    pub endorsement: Vec<u8>,
}

/// Stored endorsement for an individual group member.
///
/// Individual endorsements are combined when sending to small subsets
/// of the group.
#[derive(Clone, Debug)]
pub struct GroupSendMemberEndorsement {
    /// The group this endorsement is for.
    pub group_id: GroupV2Id,
    /// The ACI of the group member.
    pub member_aci: Aci,
    /// Expiration as Unix timestamp in seconds.
    pub expiration: u64,
    /// The serialized endorsement (compressed form for storage).
    pub endorsement: Vec<u8>,
}

/// Decoded endorsements ready for use.
#[derive(Clone, Debug)]
pub struct GroupSendEndorsementsData {
    /// Combined endorsement for all members.
    pub combined_endorsement: GroupSendCombinedEndorsement,
    /// Per-member endorsements.
    pub member_endorsements: Vec<GroupSendMemberEndorsement>,
}

/// Errors that can occur when working with group send endorsements.
#[derive(Debug, thiserror::Error)]
pub enum GroupSendEndorsementError {
    #[error("Empty response from server")]
    EmptyResponse,

    #[error("Member count mismatch: expected {expected}, got {actual}")]
    MemberCountMismatch { expected: usize, actual: usize },

    #[error("Missing endorsement for member")]
    MissingEndorsement,

    #[error("Endorsement has expired")]
    Expired,

    #[error("Endorsement expires too soon (within 2 hours)")]
    ExpiresSoon,

    #[error(
        "Endorsement expiration is too far in the future (more than 7 days)"
    )]
    ExpiresTooFarInFuture,

    #[error("No endorsements available for this group")]
    NoEndorsements,

    #[error("Invalid endorsement bytes")]
    InvalidEndorsement,

    #[error("ZKGroup deserialization error: {0}")]
    ZkGroup(#[from] ZkGroupDeserializationFailure),

    #[error("ZKGroup verification failed")]
    ZkGroupVerification,
}

impl From<ZkGroupVerificationFailure> for GroupSendEndorsementError {
    fn from(_: ZkGroupVerificationFailure) -> Self {
        GroupSendEndorsementError::ZkGroupVerification
    }
}

/// Decode the server's `groupSendEndorsementsResponse` into usable endorsements.
///
/// # Arguments
///
/// * `response_bytes` - Raw bytes from the `groupSendEndorsementsResponse` protobuf field
/// * `group_id` - The group's V2 ID
/// * `group_secret_params` - The group's secret params
/// * `server_public_params` - The server's public params
/// * `group_members` - List of member service IDs (including our own)
/// * `now` - Current timestamp for validation
///
/// # Returns
///
/// The combined endorsement and per-member endorsements on success.
///
/// # Errors
///
/// Returns an error if:
/// - The response is empty
/// - The member count doesn't match
/// - The endorsements fail verification
/// - The endorsements are expired or invalid
pub fn decode_group_send_endorsements_response(
    response_bytes: &[u8],
    group_id: GroupV2Id,
    group_secret_params: &GroupSecretParams,
    server_public_params: &zkgroup::ServerPublicParams,
    group_members: &[ServiceId],
    now: DateTime<Utc>,
) -> Result<GroupSendEndorsementsData, GroupSendEndorsementError> {
    if response_bytes.is_empty() {
        return Err(GroupSendEndorsementError::EmptyResponse);
    }

    // Deserialize the response
    let response: GroupSendEndorsementsResponse =
        bincode::deserialize(response_bytes)
            .map_err(|_| GroupSendEndorsementError::InvalidEndorsement)?;

    let expiration = response.expiration();
    let now_timestamp = Timestamp::from_epoch_seconds(now.timestamp() as u64);

    // Receive and validate endorsements (using single-threaded version to avoid rayon dependency)
    let received = response.receive_with_service_ids_single_threaded(
        group_members.iter().copied(),
        now_timestamp,
        group_secret_params,
        server_public_params,
    )?;

    if received.len() != group_members.len() {
        return Err(GroupSendEndorsementError::MemberCountMismatch {
            expected: group_members.len(),
            actual: received.len(),
        });
    }

    // Build combined endorsement by combining all individual ones
    let all_endorsements: Vec<_> =
        received.iter().map(|r| r.decompressed).collect();
    let combined = GroupSendEndorsement::combine(all_endorsements);

    // Map members to their endorsements
    let member_endorsements: Vec<_> = group_members
        .iter()
        .zip(received.iter())
        .filter_map(|(service_id, received_endorsement)| {
            // We only store endorsements for ACIs, not PNIs
            if let ServiceId::Aci(aci) = service_id {
                Some(GroupSendMemberEndorsement {
                    group_id,
                    member_aci: *aci,
                    expiration: expiration.epoch_seconds(),
                    endorsement: bincode::serialize(
                        &received_endorsement.compressed,
                    )
                    .expect("endorsement serialization should not fail"),
                })
            } else {
                None
            }
        })
        .collect();

    Ok(GroupSendEndorsementsData {
        combined_endorsement: GroupSendCombinedEndorsement {
            group_id,
            expiration: expiration.epoch_seconds(),
            endorsement: bincode::serialize(&combined.compress())
                .expect("endorsement serialization should not fail"),
        },
        member_endorsements,
    })
}

/// Builder for creating `GroupSendToken` for various recipient combinations.
///
/// Use this to efficiently create tokens for:
/// - All group members (use `build_token_for_all`)
/// - A subset of members (use `build_token_for_members`)
///
/// The builder automatically chooses the most efficient strategy:
/// - For single member: use their individual endorsement
/// - For large subsets (more than half): subtract excluded members
/// - For small subsets: combine individual endorsements
pub struct GroupSendTokenBuilder {
    combined_endorsement: GroupSendCombinedEndorsement,
    member_endorsements: HashMap<Aci, GroupSendMemberEndorsement>,
    group_secret_params: GroupSecretParams,
    local_aci: Aci,
}

impl GroupSendTokenBuilder {
    /// Create a new builder from stored endorsements.
    ///
    /// # Arguments
    ///
    /// * `combined` - The combined endorsement for all members
    /// * `members` - Per-member endorsements
    /// * `group_secret_params` - The group's secret params for token generation
    /// * `local_aci` - Our own ACI (needed because combined endorsement excludes sender)
    pub fn new(
        combined: GroupSendCombinedEndorsement,
        members: Vec<GroupSendMemberEndorsement>,
        group_secret_params: GroupSecretParams,
        local_aci: Aci,
    ) -> Self {
        let member_endorsements =
            members.into_iter().map(|e| (e.member_aci, e)).collect();

        Self {
            combined_endorsement: combined,
            member_endorsements,
            group_secret_params,
            local_aci,
        }
    }

    /// Total number of members with endorsements.
    pub fn member_count(&self) -> usize {
        self.member_endorsements.len()
    }

    /// The expiration timestamp of these endorsements.
    pub fn expiration(&self) -> u64 {
        self.combined_endorsement.expiration
    }

    /// Validate that endorsements haven't expired.
    ///
    /// Uses the same bounds as Signal Desktop and zkgroup:
    /// - Must expire in more than 2 hours
    /// - Must not expire more than 7 days from now
    pub fn validate_expiration(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(), GroupSendEndorsementError> {
        const TWO_HOURS: i64 = 2 * 60 * 60;
        const SEVEN_DAYS: i64 = 7 * 24 * 60 * 60;

        let now_secs = now.timestamp();
        let exp_secs = self.combined_endorsement.expiration as i64;

        let time_remaining = exp_secs - now_secs;

        if time_remaining <= TWO_HOURS {
            return Err(GroupSendEndorsementError::ExpiresSoon);
        }
        if time_remaining > SEVEN_DAYS {
            return Err(GroupSendEndorsementError::ExpiresTooFarInFuture);
        }

        Ok(())
    }

    /// Build a token for sending to all group members.
    pub fn build_token_for_all(
        &self,
    ) -> Result<GroupSendToken, GroupSendEndorsementError> {
        let endorsement: GroupSendEndorsement =
            bincode::deserialize(&self.combined_endorsement.endorsement)
                .map_err(|_| GroupSendEndorsementError::InvalidEndorsement)?;
        let token = endorsement.to_token(self.group_secret_params);
        let expiration =
            Timestamp::from_epoch_seconds(self.combined_endorsement.expiration);
        let full_token = token.into_full_token(expiration);

        Ok(GroupSendToken(
            bincode::serialize(&full_token)
                .expect("token serialization should not fail"),
        ))
    }

    /// Build a token for sending to a specific subset of group members.
    ///
    /// # Arguments
    ///
    /// * `recipients` - The ACIs of the recipients (should not include sender)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any recipient is missing an endorsement
    /// - The endorsement combination/subtraction fails
    pub fn build_token_for_members(
        &self,
        recipients: &[Aci],
    ) -> Result<GroupSendToken, GroupSendEndorsementError> {
        if recipients.is_empty() {
            return Err(GroupSendEndorsementError::NoEndorsements);
        }

        // Validate we have endorsements for all recipients
        for aci in recipients {
            if !self.member_endorsements.contains_key(aci) {
                return Err(GroupSendEndorsementError::MissingEndorsement);
            }
        }

        // Single member: use their individual endorsement directly
        if recipients.len() == 1 {
            return self.build_token_for_single_member(recipients[0]);
        }

        let total_members = self.member_endorsements.len();

        // Decide strategy based on recipient count
        // For large subsets (> half), subtract excluded members
        // For small subsets (<= half), combine individual endorsements
        if recipients.len() > total_members / 2 {
            self.build_token_by_subtraction(recipients)
        } else {
            self.build_token_by_combination(recipients)
        }
    }

    fn build_token_for_single_member(
        &self,
        recipient: Aci,
    ) -> Result<GroupSendToken, GroupSendEndorsementError> {
        let member_endorsement = self
            .member_endorsements
            .get(&recipient)
            .ok_or(GroupSendEndorsementError::MissingEndorsement)?;

        let endorsement: GroupSendEndorsement =
            bincode::deserialize(&member_endorsement.endorsement)
                .map_err(|_| GroupSendEndorsementError::InvalidEndorsement)?;
        let token = endorsement.to_token(self.group_secret_params);
        let expiration =
            Timestamp::from_epoch_seconds(member_endorsement.expiration);
        let full_token = token.into_full_token(expiration);

        Ok(GroupSendToken(
            bincode::serialize(&full_token)
                .expect("token serialization should not fail"),
        ))
    }

    fn build_token_by_subtraction(
        &self,
        recipients: &[Aci],
    ) -> Result<GroupSendToken, GroupSendEndorsementError> {
        // Start with combined endorsement for all members
        let combined: GroupSendEndorsement =
            bincode::deserialize(&self.combined_endorsement.endorsement)
                .map_err(|_| GroupSendEndorsementError::InvalidEndorsement)?;

        // Find excluded members (those not in recipients list, excluding ourselves)
        let recipient_set: std::collections::HashSet<_> =
            recipients.iter().copied().collect();
        let excluded: Vec<_> = self
            .member_endorsements
            .keys()
            .filter(|aci| {
                **aci != self.local_aci && !recipient_set.contains(aci)
            })
            .copied()
            .collect();

        // For each excluded member, remove their endorsement from combined
        let mut result = combined;
        for excluded_aci in excluded {
            let member_endorsement = self
                .member_endorsements
                .get(&excluded_aci)
                .ok_or(GroupSendEndorsementError::MissingEndorsement)?;

            let exclusion_endorsement: GroupSendEndorsement =
                bincode::deserialize(&member_endorsement.endorsement).map_err(
                    |_| GroupSendEndorsementError::InvalidEndorsement,
                )?;
            result = result.remove(&exclusion_endorsement);
        }

        let token = result.to_token(self.group_secret_params);
        let expiration =
            Timestamp::from_epoch_seconds(self.combined_endorsement.expiration);
        let full_token = token.into_full_token(expiration);

        Ok(GroupSendToken(
            bincode::serialize(&full_token)
                .expect("token serialization should not fail"),
        ))
    }

    fn build_token_by_combination(
        &self,
        recipients: &[Aci],
    ) -> Result<GroupSendToken, GroupSendEndorsementError> {
        // Collect endorsements for all recipients
        let endorsements: Vec<_> = recipients
            .iter()
            .map(|aci| {
                let member = self
                    .member_endorsements
                    .get(aci)
                    .ok_or(GroupSendEndorsementError::MissingEndorsement)?;
                let endorsement: GroupSendEndorsement = bincode::deserialize(
                    &member.endorsement,
                )
                .map_err(|_| GroupSendEndorsementError::InvalidEndorsement)?;
                Ok(endorsement)
            })
            .collect::<Result<Vec<_>, GroupSendEndorsementError>>()?;

        // Combine all endorsements
        let combined = GroupSendEndorsement::combine(endorsements);
        let token = combined.to_token(self.group_secret_params);
        let expiration =
            Timestamp::from_epoch_seconds(self.combined_endorsement.expiration);
        let full_token = token.into_full_token(expiration);

        Ok(GroupSendToken(
            bincode::serialize(&full_token)
                .expect("token serialization should not fail"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_send_token_base64() {
        let token = GroupSendToken::from_bytes(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(token.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(token.to_base64(), "AQIDBA==");
    }

    #[test]
    fn test_group_id() {
        let group_id = GroupV2Id::from([0u8; 32]);
        let endorsement = GroupSendCombinedEndorsement {
            group_id: group_id.clone(),
            expiration: 0,
            endorsement: vec![],
        };
        assert_eq!(endorsement.group_id, group_id);
    }

    #[test]
    fn test_empty_response_error() {
        let server_secret_params =
            zkgroup::ServerSecretParams::generate([0u8; 32]);
        let server_public_params = server_secret_params.get_public_params();

        let result = decode_group_send_endorsements_response(
            &[],
            GroupV2Id::from([0u8; 32]),
            &GroupSecretParams::generate([1u8; 32]),
            &server_public_params,
            &[],
            Utc::now(),
        );
        assert!(matches!(
            result,
            Err(GroupSendEndorsementError::EmptyResponse)
        ));
    }

    #[test]
    fn test_expiration_validation() {
        let now = Utc::now();
        let two_hours_secs = 2 * 60 * 60;
        let seven_days_secs = 7 * 24 * 60 * 60;

        // Create a builder with endorsement expiring in 3 hours (valid)
        let valid_builder = GroupSendTokenBuilder {
            combined_endorsement: GroupSendCombinedEndorsement {
                group_id: GroupV2Id::from([0u8; 32]),
                expiration: (now.timestamp() + 3 * two_hours_secs / 2) as u64,
                endorsement: vec![],
            },
            member_endorsements: HashMap::new(),
            group_secret_params: GroupSecretParams::generate([0u8; 32]),
            local_aci: Aci::from_uuid_bytes([0u8; 16]),
        };
        assert!(valid_builder.validate_expiration(now).is_ok());

        // Create a builder with endorsement expiring in 1 hour (too soon)
        let expiring_builder = GroupSendTokenBuilder {
            combined_endorsement: GroupSendCombinedEndorsement {
                group_id: GroupV2Id::from([0u8; 32]),
                expiration: (now.timestamp() + two_hours_secs / 2) as u64,
                endorsement: vec![],
            },
            member_endorsements: HashMap::new(),
            group_secret_params: GroupSecretParams::generate([0u8; 32]),
            local_aci: Aci::from_uuid_bytes([0u8; 16]),
        };
        assert!(matches!(
            expiring_builder.validate_expiration(now),
            Err(GroupSendEndorsementError::ExpiresSoon)
        ));

        // Create a builder with endorsement expiring in 10 days (too far)
        let far_future_builder = GroupSendTokenBuilder {
            combined_endorsement: GroupSendCombinedEndorsement {
                group_id: GroupV2Id::from([0u8; 32]),
                expiration: (now.timestamp() + 10 * seven_days_secs / 7) as u64,
                endorsement: vec![],
            },
            member_endorsements: HashMap::new(),
            group_secret_params: GroupSecretParams::generate([0u8; 32]),
            local_aci: Aci::from_uuid_bytes([0u8; 16]),
        };
        assert!(matches!(
            far_future_builder.validate_expiration(now),
            Err(GroupSendEndorsementError::ExpiresTooFarInFuture)
        ));
    }
}
