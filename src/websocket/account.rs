use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    content::ServiceError,
    proto::DeviceName,
    utils::{
        serde_device_id, serde_e164, serde_optional_base64,
        serde_optional_base64_url_safe_no_pad, serde_optional_prost_base64,
    },
    websocket,
};

use super::SignalWebSocket;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    #[serde(with = "serde_device_id")]
    pub device_id: libsignal_core::DeviceId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    #[serde(with = "serde_device_id")]
    pub id: libsignal_core::DeviceId,
    pub registration_id: i32,
    pub name: Option<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceInfoEncrypted {
    #[serde(with = "serde_device_id")]
    pub id: libsignal_core::DeviceId,
    pub name: Option<String>,
    pub registration_id: i32,
    pub created_at_ciphertext: String,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// kept in sync with https://github.com/signalapp/Signal-Server/blob/main/service/src/main/java/org/whispersystems/textsecuregcm/entities/AccountAttributes.java#L25
pub struct AccountAttributes {
    pub registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_lock: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<DeviceCapabilities>,
    #[serde(default, with = "serde_optional_prost_base64")]
    pub name: Option<DeviceName>,
    pub pni_registration_id: u32,
    #[serde(
        default,
        with = "serde_optional_base64",
        skip_serializing_if = "Option::is_none"
    )]
    pub recovery_password: Option<Vec<u8>>,
}

// Keep in sync with https://github.com/signalapp/Signal-Server/blob/main/service/src/main/java/org/whispersystems/textsecuregcm/storage/DeviceCapability.java.
// When updating this, also consider updating LinkCapabilities.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    #[serde(default)]
    pub storage: bool,
    #[serde(default)]
    pub transfer: bool,
    #[serde(default)]
    pub attachment_backfill: bool,
    #[serde(default)]
    pub spqr: bool,
    // For some reason, this uses snake case while everything else uses camel case.
    #[serde(default, rename = "profiles_v2")]
    pub profiles_v2: bool,
    #[serde(default)]
    pub username_change_sync_message: bool,
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        DeviceCapabilities {
            storage: false,
            transfer: false,
            attachment_backfill: false,
            spqr: true,
            profiles_v2: false,
            username_change_sync_message: false,
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn device_capabilities_serialization_weird_casing() {
        let capabilities = super::DeviceCapabilities::default();
        let json = serde_json::to_string(&capabilities)
            .expect("Serialize capabilities");
        assert!(json.contains("usernameChangeSyncMessage"));
        assert!(json.contains("profiles_v2"));
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoAmIResponse {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    #[serde(default)] // nil when not present (yet)
    pub pni: Uuid,
    #[serde(with = "serde_e164")]
    pub number: libsignal_core::E164,
    /// Hash of the account's username, if one is set.
    #[serde(default, with = "serde_optional_base64_url_safe_no_pad")]
    pub username_hash: Option<Vec<u8>>,
    /// Handle (UUID) of the account's username link, if one is set.
    ///
    /// Decrypting the username also requires the link entropy, which the
    /// server never sees; only the full `signal.me` link carries it.
    #[serde(default)]
    pub username_link_handle: Option<Uuid>,
}

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
    }

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    pub(crate) async fn devices(
        &mut self,
    ) -> Result<Vec<DeviceInfoEncrypted>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct DeviceInfoList {
            devices: Vec<DeviceInfoEncrypted>,
        }

        let devices: DeviceInfoList = self
            .http_request(Method::GET, "/v1/devices")?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        Ok(devices.devices)
    }

    pub async fn set_account_attributes(
        &mut self,
        attributes: AccountAttributes,
    ) -> Result<(), ServiceError> {
        self.http_request(Method::PUT, "/v1/accounts/attributes")?
            .send_json(&attributes)
            .await?
            .service_error_for_status()
            .await?;

        Ok(())
    }

    /// Unregister and delete the account from Signal servers.
    ///
    /// This permanently deletes the account and all associated data (groups, contacts, messages).
    /// After calling this, the phone number can be re-registered with a fresh account.
    ///
    /// CAUTION: This is irreversible. All account data will be lost.
    pub async fn unregister_account(&mut self) -> Result<(), ServiceError> {
        self.http_request(Method::DELETE, "/v1/accounts/me")?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        Ok(())
    }
}
