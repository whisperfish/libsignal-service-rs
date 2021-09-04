use phonenumber::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{push_service::ServiceError, session_store::SessionStoreExt};

#[derive(thiserror::Error, Debug)]
pub enum ParseServiceAddressError {
    #[error("Supplied phone number could not be parsed in E164 format")]
    InvalidPhoneNumber(#[from] phonenumber::ParseError),

    #[error("Supplied uuid could not be parsed")]
    InvalidUuidError(#[from] uuid::Error),

    #[error("Envelope with neither Uuid or E164")]
    NoSenderError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceAddress {
    pub uuid: Option<Uuid>,
    pub phonenumber: Option<PhoneNumber>,
    pub relay: Option<String>,
}

impl ServiceAddress {
    /// Formats the phone number, if present, as E164
    pub fn e164(&self) -> Option<String> {
        self.phonenumber
            .as_ref()
            .map(|pn| pn.format().mode(phonenumber::Mode::E164).to_string())
    }

    pub async fn sub_device_sessions(
        &self,
        session_store: &dyn SessionStoreExt,
    ) -> Result<Vec<u32>, ServiceError> {
        let mut sub_device_sessions = Vec::new();
        if let Some(uuid) = &self.uuid {
            sub_device_sessions.extend(
                session_store
                    .get_sub_device_sessions(&uuid.to_string())
                    .await?,
            );
        }
        if let Some(e164) = &self.e164() {
            sub_device_sessions
                .extend(session_store.get_sub_device_sessions(e164).await?);
        }
        Ok(sub_device_sessions)
    }
}

impl std::fmt::Display for ServiceAddress {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        match (&self.uuid, &self.phonenumber, &self.relay) {
            (_, Some(e164), _) => write!(f, "ServiceAddress({})", e164),
            (Some(uuid), _, _) => write!(f, "ServiceAddress({})", uuid),
            _ => write!(f, "ServiceAddress(INVALID)"),
        }
    }
}

impl ServiceAddress {
    pub fn parse(
        e164: Option<&str>,
        uuid: Option<&str>,
    ) -> Result<ServiceAddress, ParseServiceAddressError> {
        let phonenumber =
            e164.map(|s| phonenumber::parse(None, s)).transpose()?;
        let uuid = uuid.map(Uuid::parse_str).transpose()?;

        Ok(ServiceAddress {
            phonenumber,
            uuid,
            relay: None,
        })
    }

    /// Returns uuid if present, e164 otherwise.
    pub fn identifier(&self) -> String {
        if let Some(ref uuid) = self.uuid {
            return uuid.to_string();
        } else if let Some(e164) = self.e164() {
            return e164;
        }
        unreachable!(
            "an address requires either a UUID or a E164 phone number"
        );
    }

    pub fn matches(&self, other: &Self) -> bool {
        (self.phonenumber.is_some() && self.phonenumber == other.phonenumber)
            || (self.uuid.is_some() && self.uuid == other.uuid)
    }
}

impl From<Uuid> for ServiceAddress {
    fn from(uuid: Uuid) -> Self {
        ServiceAddress {
            uuid: Some(uuid),
            phonenumber: None,
            relay: None,
        }
    }
}

impl From<PhoneNumber> for ServiceAddress {
    fn from(phone_number: PhoneNumber) -> Self {
        ServiceAddress {
            uuid: None,
            phonenumber: Some(phone_number),
            relay: None,
        }
    }
}
