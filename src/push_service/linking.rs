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
pub struct LinkCapabilities {
    pub delete_sync: bool,
    pub versioned_expiration_timer: bool,
    /// It is currently unclear what this field is.
    ///
    /// Signal Server refers to the field as `STORAGE_SERVICE_RECORD_KEY_ROTATION` [here](https://github.com/signalapp/Signal-Server/blob/5cc76f48aa4028f5001a51409a3a0e4e6ce2d7f2/service/src/main/java/org/whispersystems/textsecuregcm/storage/DeviceCapability.java#L15).
    /// Signal Android refers to the field as `storageServiceEncryptionV2` [here](https://github.com/signalapp/Signal-Android/blob/ec840726fcbb5440e1337274f791d17a6fe59598/libsignal-service/src/main/java/org/whispersystems/signalservice/api/account/AccountAttributes.kt#L60).
    /// It is therefore possibly related to backup
    pub ssre2: bool,
}

// https://github.com/signalapp/Signal-Desktop/blob/1e57db6aa4786dcddc944349e4894333ac2ffc9e/ts/textsecure/WebAPI.ts#L1287
impl Default for LinkCapabilities {
    fn default() -> Self {
        Self {
            delete_sync: true,
            versioned_expiration_timer: true,
            ssre2: true,
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
