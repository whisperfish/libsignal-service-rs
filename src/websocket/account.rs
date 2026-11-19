use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    content::ServiceError,
    proto::DeviceName,
    push_service::response::SignalServiceResponse,
    utils::{
        serde_device_id, serde_optional_base64, serde_optional_prost_base64,
    },
    websocket,
};

use libsignal_net_grpc::proto::chat::account::{
    accounts_client::AccountsClient, GetAccountIdentityRequest,
};
use libsignal_net_grpc::proto::chat::common::IdentityType;
use libsignal_net_grpc::proto::chat::device::{
    devices_client::DevicesClient, set_device_name_response, GetDevicesRequest,
    SetDeviceNameRequest,
};
use prost::Message;

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

#[derive(Debug)]
pub(crate) struct DeviceInfoEncrypted {
    pub id: libsignal_core::DeviceId,
    pub name: Option<Vec<u8>>,
    pub registration_id: i32,
    pub created_at_ciphertext: Vec<u8>,
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

#[derive(Debug)]
pub struct WhoAmIResponse {
    pub aci: Uuid,
    /// Nil when the account has no PNI (yet).
    pub pni: Uuid,
    pub number: libsignal_core::E164,
    pub username_hash: Option<Vec<u8>>,
    /// Decrypting the username also requires the link entropy, which only the
    /// full `signal.me` link carries.
    pub username_link_handle: Option<Uuid>,
}

impl SignalWebSocket<websocket::Identified> {
    /// Method used to check our own UUID
    pub async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        const INVALID: ServiceError = ServiceError::InvalidFrame {
            reason: "invalid GetAccountIdentity response",
        };
        let ids = AccountsClient::new(self.grpc.authenticated()?)
            .get_account_identity(GetAccountIdentityRequest {})
            .await?
            .into_inner()
            .account_identifiers
            .ok_or(INVALID)?;
        let uuid_of = |kind: IdentityType| {
            ids.service_identifiers
                .iter()
                .find(|id| id.identity_type() == kind)
                .map(|id| Uuid::from_slice(&id.uuid).map_err(|_| INVALID))
                .transpose()
        };
        Ok(WhoAmIResponse {
            aci: uuid_of(IdentityType::Aci)?.ok_or(INVALID)?,
            pni: uuid_of(IdentityType::Pni)?.unwrap_or_default(),
            number: ids.e164.parse().map_err(|_| INVALID)?,
            username_hash: (!ids.username_hash.is_empty())
                .then_some(ids.username_hash),
            username_link_handle: (!ids.username_link_handle.is_empty())
                .then(|| Uuid::from_slice(&ids.username_link_handle))
                .transpose()
                .map_err(|_| INVALID)?,
        })
    }

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    pub(crate) async fn devices(
        &mut self,
    ) -> Result<Vec<DeviceInfoEncrypted>, ServiceError> {
        DevicesClient::new(self.grpc.authenticated()?)
            .get_devices(GetDevicesRequest {})
            .await?
            .into_inner()
            .devices
            .into_iter()
            .map(|d| {
                Ok(DeviceInfoEncrypted {
                    id: libsignal_core::DeviceId::try_from(d.id)?,
                    name: (!d.name.is_empty()).then_some(d.name),
                    registration_id: i32::try_from(d.registration_id).map_err(
                        |_| ServiceError::InvalidFrame {
                            reason: "registration id out of range",
                        },
                    )?,
                    created_at_ciphertext: d.created_at_ciphertext,
                    last_seen: DateTime::from_timestamp_millis(
                        d.last_seen as i64,
                    )
                    .unwrap_or_default(),
                })
            })
            .collect()
    }

    pub(crate) async fn set_device_name(
        &mut self,
        id: libsignal_core::DeviceId,
        name: &DeviceName,
    ) -> Result<(), ServiceError> {
        use set_device_name_response::Response;
        let response = DevicesClient::new(self.grpc.authenticated()?)
            .set_device_name(SetDeviceNameRequest {
                name: name.encode_to_vec(),
                id: u8::from(id).into(),
            })
            .await?
            .into_inner();
        match response.response {
            Some(Response::Success(())) => Ok(()),
            Some(Response::TargetDeviceNotFound(_)) => {
                Err(ServiceError::NotFoundError)
            },
            None => Err(ServiceError::InvalidFrame {
                reason: "empty SetDeviceName response",
            }),
        }
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

    /// Replace this device's capabilities, leaving the account's attributes alone.
    ///
    /// A linked device uses this instead of `set_account_attributes`, whose
    /// registration lock, discoverability and access key apply to the whole account.
    pub async fn set_device_capabilities(
        &mut self,
        capabilities: &DeviceCapabilities,
    ) -> Result<(), ServiceError> {
        self.http_request(Method::PUT, "/v1/devices/capabilities")?
            .send_json(capabilities)
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
