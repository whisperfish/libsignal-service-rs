use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    content::ServiceError, proto::DeviceName, utils::{serde_device_id, serde_e164, serde_optional_base64, serde_optional_prost_base64}, websocket
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
    pub fetches_messages: bool,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    #[serde(default, with = "serde_optional_prost_base64")]
    pub name: Option<DeviceName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_lock: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub capabilities: DeviceCapabilities,
    pub discoverable_by_phone_number: bool,    
    pub pin: Option<String>,
    #[serde(default, with = "serde_optional_base64", skip_serializing_if = "Option::is_none")]
    pub recovery_password: Option<Vec<u8>>,
}

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
}

impl Default for DeviceCapabilities {
    fn default() -> Self {
        DeviceCapabilities {
            storage: false,
            transfer: false,
            attachment_backfill: false,
            spqr: true,
        }
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
        assert!(
            attributes.pin.is_none() || attributes.registration_lock.is_none(),
            "only one of PIN and registration lock can be set."
        );

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
