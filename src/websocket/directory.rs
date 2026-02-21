//! Contact Discovery Service (CDSI) authentication
//!
//! Provides authentication credentials for CDSI contact lookup operations.

use crate::content::ServiceError;
use crate::websocket::{Identified, SignalWebSocket};
use reqwest::Method;
use serde::Deserialize;

/// CDSI authentication credentials
#[derive(Debug, Deserialize)]
pub struct CdsiAuth {
    pub username: String,
    pub password: String,
}

impl SignalWebSocket<Identified> {
    /// Get CDSI authentication credentials from the chat server.
    ///
    /// Returns username/password credentials for establishing an
    /// authenticated connection to the Contact Discovery Service.
    ///
    /// # Returns
    /// * `Ok(CdsiAuth)` - Authentication credentials
    /// * `Err(ServiceError)` - Network or protocol error
    ///
    /// # Example
    /// ```no_run
    /// # use libsignal_service::websocket::{SignalWebSocket, Identified};
    /// # async fn example(mut ws: SignalWebSocket<Identified>) {
    /// let auth = ws.get_cdsi_auth().await.unwrap();
    /// // Use auth.username and auth.password for CDSI connection
    /// # }
    /// ```
    pub async fn get_cdsi_auth(&mut self) -> Result<CdsiAuth, ServiceError> {
        let response = self
            .http_request(Method::GET, "/v2/directory/auth")?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response.json().await
    }
}
