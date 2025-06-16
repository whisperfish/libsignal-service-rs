use reqwest::Method;

use crate::{content::ServiceError, push_service::WhoAmIResponse, websocket};

use super::SignalWebSocket;

impl SignalWebSocket<websocket::Identified> {
    /// Method used to check our own UUID
    pub async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        self.http_request(Method::GET, "/v1/accounts/whoami")?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}
