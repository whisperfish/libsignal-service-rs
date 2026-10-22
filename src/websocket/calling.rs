use reqwest::Method;
use serde::Deserialize;

use crate::{
    push_service::response::SignalServiceResponse,
    websocket::{self, SignalWebSocket},
};

use super::ServiceError;

/// Short-lived TURN credentials for 1:1 calls.
///
/// The URLs are TURN URIs (RFC 7065, e.g. `turn:host:3478?transport=udp`), meant to be
/// handed to WebRTC as they are. `urls_with_ips` must be paired with `hostname` for TLS
/// validation; `urls` can be used as-is.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnServer {
    pub username: String,
    pub password: String,
    #[serde(rename = "ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub urls_with_ips: Vec<String>,
    pub hostname: Option<String>,
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn get_calling_relays(
        &mut self,
    ) -> Result<Vec<TurnServer>, ServiceError> {
        #[derive(Deserialize)]
        struct GetCallingRelaysResponse {
            relays: Vec<TurnServer>,
        }

        let response: GetCallingRelaysResponse = self
            .http_request(Method::GET, "/v2/calling/relays")?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        Ok(response.relays)
    }
}
