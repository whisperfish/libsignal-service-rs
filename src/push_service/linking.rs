use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::configuration::Endpoint;

use super::{
    response::ReqwestExt, DeviceActivationRequest, HttpAuth, HttpAuthOverride,
    PushService, ServiceError,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAccountAttributes {
    pub fetches_messages: bool,
    pub name: String,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub capabilities: LinkCapabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkCapabilities {
    pub delete_sync: bool,
    pub versioned_expiration_timer: bool,
}

// https://github.com/signalapp/Signal-Desktop/blob/1e57db6aa4786dcddc944349e4894333ac2ffc9e/ts/textsecure/WebAPI.ts#L1287
impl Default for LinkCapabilities {
    fn default() -> Self {
        Self {
            delete_sync: true,
            versioned_expiration_timer: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    pub pni: Uuid,
    pub device_id: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequest {
    pub verification_code: String,
    pub account_attributes: LinkAccountAttributes,
    #[serde(flatten)]
    pub device_activation_request: DeviceActivationRequest,
}

impl PushService {
    pub async fn link_device(
        &mut self,
        link_request: &LinkRequest,
        http_auth: HttpAuth,
    ) -> Result<LinkResponse, ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::Service,
            "/v1/devices/link",
            HttpAuthOverride::Identified(http_auth),
        )?
        .json(&link_request)
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    pub async fn unlink_device(&mut self, id: i64) -> Result<(), ServiceError> {
        self.request(
            Method::DELETE,
            Endpoint::Service,
            format!("/v1/devices/{}", id),
            HttpAuthOverride::NoOverride,
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?;

        Ok(())
    }
}
