//! Helper functions for profile key credential operations.
//!
//! These are used for group creation and member addition, where the Signal
//! server requires a ProfileKeyCredentialPresentation (ZK proof) for each member.

use libsignal_protocol::Aci;
use zkgroup::{
    profiles::{
        ExpiringProfileKeyCredential, ExpiringProfileKeyCredentialResponse,
        ProfileKey, ProfileKeyCredentialRequest,
        ProfileKeyCredentialRequestContext,
    },
    ServerPublicParams, Timestamp, ZkGroupVerificationFailure,
};

/// Create a ProfileKeyCredentialRequest for fetching a credential from the server.
///
/// Returns a tuple of:
/// - `ProfileKeyCredentialRequestContext` - needed to process the server's response
/// - `ProfileKeyCredentialRequest` - the request to send to the profile API
///
/// The request should be hex-encoded and sent as a query parameter to
/// `GET /v1/profile/{uuid}/{version}?credentialType=expiringProfileKey&credentialRequest=...`
pub fn create_credential_request(
    server_public_params: &ServerPublicParams,
    aci: Aci,
    profile_key: &ProfileKey,
) -> (
    ProfileKeyCredentialRequestContext,
    ProfileKeyCredentialRequest,
) {
    let randomness: [u8; 32] = rand::random();
    let context = server_public_params
        .create_profile_key_credential_request_context(
            randomness,
            aci,
            *profile_key,
        );
    let request = context.get_request();
    (context, request)
}

/// Process a credential response from the server.
///
/// This verifies the server's response and extracts the `ExpiringProfileKeyCredential`
/// that can be used to create presentations for group operations.
///
/// # Arguments
/// * `server_public_params` - The server's public parameters
/// * `context` - The context from `create_credential_request`
/// * `response` - The response received from the profile API
///
/// # Returns
/// The verified `ExpiringProfileKeyCredential`, or an error if verification fails.
pub fn receive_credential(
    server_public_params: &ServerPublicParams,
    context: &ProfileKeyCredentialRequestContext,
    response: &ExpiringProfileKeyCredentialResponse,
) -> Result<ExpiringProfileKeyCredential, ZkGroupVerificationFailure> {
    let current_time_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();
    let current_time = Timestamp::from_epoch_seconds(current_time_secs);

    server_public_params.receive_expiring_profile_key_credential(
        context,
        response,
        current_time,
    )
}

#[cfg(test)]
mod tests {
    // Integration tests would go here, but they require valid server params
    // and network access to actually test credential fetching.
}
