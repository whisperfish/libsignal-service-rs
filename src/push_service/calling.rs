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
    #[deprecated(
        note = "Use get_turn_server_info_v2 instead. This method is still used by the Android and iOS clients, and will be kept in as long as that's the case."
    )]
    pub async fn get_turn_server_info(
        &mut self,
    ) -> Result<TurnServerInfo, ServiceError> {
        Ok(self
            .request(
                Method::GET,
                Endpoint::service("/v1/calling/relays"),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?)
    }

    pub async fn get_turn_server_info_v2(
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
