use std::fmt;

use chrono::{DateTime, Utc};
use phonenumber::PhoneNumber;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    response::ReqwestExt, HttpAuthOverride, PushService, ServiceError,
};
use crate::{
    configuration::Endpoint,
    utils::{serde_optional_base64, serde_phone_number},
};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ServiceIdType {
    /// Account Identity (ACI)
    ///
    /// An account UUID without an associated phone number, probably in the future to a username
    AccountIdentity,
    /// Phone number identity (PNI)
    ///
    /// A UUID associated with a phone number
    PhoneNumberIdentity,
}

impl fmt::Display for ServiceIdType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdType::AccountIdentity => f.write_str("aci"),
            ServiceIdType::PhoneNumberIdentity => f.write_str("pni"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceIds {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    #[serde(default)] // nil when not present (yet)
    pub pni: Uuid,
}

impl ServiceIds {
    pub fn aci(&self) -> libsignal_protocol::Aci {
        libsignal_protocol::Aci::from_uuid_bytes(self.aci.into_bytes())
    }

    pub fn pni(&self) -> libsignal_protocol::Pni {
        libsignal_protocol::Pni::from_uuid_bytes(self.pni.into_bytes())
    }
}

impl fmt::Display for ServiceIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aci={} pni={}", self.aci, self.pni)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    pub device_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: i64,
    pub name: Option<String>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAttributes {
    #[serde(default, with = "serde_optional_base64")]
    pub signaling_key: Option<Vec<u8>>,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    pub pin: Option<String>,
    pub registration_lock: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    pub capabilities: DeviceCapabilities,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Eq, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCapabilities {
    #[serde(default)]
    pub storage: bool,
    #[serde(default)]
    pub sender_key: bool,
    #[serde(default)]
    pub announcement_group: bool,
    #[serde(default)]
    pub change_number: bool,
    #[serde(default)]
    pub stories: bool,
    #[serde(default)]
    pub gift_badges: bool,
    #[serde(default)]
    pub pni: bool,
    #[serde(default)]
    pub payment_activation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhoAmIResponse {
    pub uuid: Uuid,
    #[serde(default)] // nil when not present (yet)
    pub pni: Uuid,
    #[serde(with = "serde_phone_number")]
    pub number: PhoneNumber,
}

impl PushService {
    /// Method used to check our own UUID
    pub async fn whoami(&mut self) -> Result<WhoAmIResponse, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::Service,
            "/v1/accounts/whoami",
            HttpAuthOverride::NoOverride,
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Fetches a list of all devices tied to the authenticated account.
    ///
    /// This list include the device that sends the request.
    pub async fn devices(&mut self) -> Result<Vec<DeviceInfo>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct DeviceInfoList {
            devices: Vec<DeviceInfo>,
        }

        let devices: DeviceInfoList = self
            .request(
                Method::GET,
                Endpoint::Service,
                "/v1/devices/",
                HttpAuthOverride::NoOverride,
            )?
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

        self.request(
            Method::PUT,
            Endpoint::Service,
            "/v1/accounts/attributes/",
            HttpAuthOverride::NoOverride,
        )?
        .json(&attributes)
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }
}
