use reqwest::Method;

use crate::{
    configuration::Endpoint,
    content::ServiceError,
    push_service::{HttpAuthOverride, WhoAmIResponse},
    websocket,
};

use super::SignalWebSocket;

impl SignalWebSocket<websocket::Identified> {
    /// Method used to check our own UUID
    pub async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        todo!();
        // self.request(
        //     Method::GET,
        //     Endpoint::service("/v1/accounts/whoami"),
        //     HttpAuthOverride::NoOverride,
        // )?
        // .send()
        // .await?
        // .service_error_for_status()
        // .await?
        // .json()
        // .await
        // .map_err(Into::into)
    }
}
