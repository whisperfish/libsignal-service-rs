use libsignal_core::DeviceId;
use reqwest::Method;

use crate::websocket::{self, SignalWebSocket};

use super::ServiceError;

impl SignalWebSocket<websocket::Identified> {
    pub async fn unlink_device(
        &mut self,
        id: DeviceId,
    ) -> Result<(), ServiceError> {
        self.http_request(Method::DELETE, format!("/v1/devices/{}", id))?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        Ok(())
    }
}
