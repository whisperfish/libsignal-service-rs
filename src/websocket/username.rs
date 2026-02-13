//! Username lookup operations
//!
//! Provides username-to-ACI resolution via Signal's username hash endpoint.

use crate::content::ServiceError;
use crate::websocket::{Identified, SignalWebSocket};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use libsignal_protocol::Aci;
use reqwest::Method;
use serde::Deserialize;
use usernames::Username;

#[derive(Debug, Deserialize)]
struct UsernameHashResponse {
    uuid: String,
}

impl SignalWebSocket<Identified> {
    /// Look up a Signal username and return the associated ACI.
    ///
    /// # Arguments
    /// * `username` - Signal username (e.g., "matt.42")
    ///
    /// # Returns
    /// * `Ok(Some(Aci))` - Username found, returns the ACI
    /// * `Ok(None)` - Username not found (404)
    /// * `Err(ServiceError)` - Network or protocol error
    ///
    /// # Example
    /// ```no_run
    /// # use libsignal_service::websocket::{SignalWebSocket, Identified};
    /// # async fn example(mut ws: SignalWebSocket<Identified>) {
    /// match ws.lookup_username("matt.42").await {
    ///     Ok(Some(aci)) => println!("Found: {}", aci.service_id_string()),
    ///     Ok(None) => println!("Username not registered"),
    ///     Err(e) => eprintln!("Error: {}", e),
    /// }
    /// # }
    /// ```
    pub async fn lookup_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Aci>, ServiceError> {
        // Parse and hash the username using Signal's canonical algorithm
        let parsed = Username::new(username).map_err(|e| ServiceError::SendError {
            reason: format!("Invalid username: {}", e),
        })?;
        let hash = parsed.hash();

        self.lookup_username_hash(&hash).await
    }

    /// Look up a username hash and return the associated ACI.
    ///
    /// Lower-level method that accepts a pre-computed hash. Most callers should
    /// use `lookup_username` instead.
    pub async fn lookup_username_hash(
        &mut self,
        username_hash: &[u8; 32],
    ) -> Result<Option<Aci>, ServiceError> {
        let encoded = URL_SAFE_NO_PAD.encode(username_hash);
        let path = format!("/v1/accounts/username_hash/{}", encoded);

        let response = self.http_request(Method::GET, &path)?.send().await?;

        // Check for 404 before calling service_error_for_status
        if response.status() == 404 {
            return Ok(None);
        }

        let response = response.service_error_for_status().await?;
        let body: UsernameHashResponse = response.json().await?;
        let uuid: uuid::Uuid = body.uuid.parse().map_err(|e| ServiceError::SendError {
            reason: format!("Invalid UUID in response: {}", e),
        })?;
        Ok(Some(uuid.into()))
    }
}
