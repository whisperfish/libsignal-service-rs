use super::{HttpAuthOverride, PushService, ReqwestExt, ServiceError};
use crate::configuration::Endpoint;
use reqwest::Method;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnServerInfo {
    pub username: String,
    pub password: String,
    pub hostname: Option<String>,
    pub urls: Vec<String>,
    #[serde(default)]
    pub urls_with_ips: Vec<String>,
}

impl PushService {
    pub async fn get_turn_server_info(
        &mut self,
    ) -> Result<Vec<TurnServerInfo>, ServiceError> {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct GetRelaysResponse {
            relays: Vec<TurnServerInfo>,
        }

        Ok(self
            .request(
                Method::GET,
                Endpoint::service("/v2/calling/relays"),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json::<GetRelaysResponse>()
            .await?
            .relays)
    }
}
