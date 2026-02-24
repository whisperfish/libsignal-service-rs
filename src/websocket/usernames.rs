use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;

use crate::content::ServiceError;

use super::{SignalWebSocket, Unidentified};

impl SignalWebSocket<Unidentified> {
    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }
}
