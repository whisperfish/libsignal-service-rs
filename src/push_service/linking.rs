use libsignal_core::DeviceId;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    configuration::Endpoint, utils::serde_device_id,
    websocket::registration::DeviceActivationRequest,
};

use super::{
    response::ReqwestExt, HttpAuth, HttpAuthOverride, PushService, ServiceError,
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
// Keep in sync with https://github.com/signalapp/Signal-Desktop/blob/main/ts/types/Capabilities.d.ts.
pub struct LinkCapabilities {
    pub attachment_backfill: bool,
    /// Sparse Post-Quantum Ratchet (`SPARSE_POST_QUANTUM_RATCHET` on Signal Server).
    ///
    /// Required for all devices; the server returns 409 if a linking device omits this capability
    /// while the account already has it on any existing device.
    pub spqr: bool,
    pub username_change_sync_message: bool,
}

// https://github.com/signalapp/Signal-Desktop/blob/1e57db6aa4786dcddc944349e4894333ac2ffc9e/ts/textsecure/WebAPI.ts#L1287
impl Default for LinkCapabilities {
    fn default() -> Self {
        Self {
            attachment_backfill: false,
            spqr: true,
            username_change_sync_message: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    pub pni: Uuid,
    #[serde(with = "serde_device_id")]
    pub device_id: DeviceId,
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
            Endpoint::service("/v1/devices/link"),
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
}
