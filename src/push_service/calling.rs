use super::{HttpAuthOverride, PushService, ServiceError};
use crate::configuration::Endpoint;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnServerInfo {
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub urls: Vec<String>,
    pub urls_with_ips: Vec<String>,
}

impl PushService {
    pub async fn get_turn_server_info(
        &mut self,
    ) -> Result<TurnServerInfo, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v1/calling/relays",
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }
}
