use std::convert::TryFrom;

use libsignal_protocol::{DeviceId, ProtocolAddress};
use uuid::Uuid;

pub use crate::push_service::ServiceIdType;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ParseServiceAddressError {
    #[error("Supplied UUID could not be parsed")]
    InvalidUuid(#[from] uuid::Error),

    #[error("Envelope without UUID")]
    NoUuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ServiceAddress {
    pub uuid: Uuid,
    pub identity: ServiceIdType,
}

impl ServiceAddress {
    pub fn to_protocol_address(
        &self,
        device_id: impl Into<DeviceId>,
    ) -> ProtocolAddress {
        match self.identity {
            ServiceIdType::AccountIdentity => {
                ProtocolAddress::new(self.uuid.to_string(), device_id.into())
            },
            ServiceIdType::PhoneNumberIdentity => ProtocolAddress::new(
                format!("PNI:{}", self.uuid),
                device_id.into(),
            ),
        }
    }

    pub fn new_aci(uuid: Uuid) -> Self {
        Self {
            uuid,
            identity: ServiceIdType::AccountIdentity,
        }
    }

    pub fn new_pni(uuid: Uuid) -> Self {
        Self {
            uuid,
            identity: ServiceIdType::PhoneNumberIdentity,
        }
    }

    pub fn aci(&self) -> Option<libsignal_protocol::Aci> {
        use libsignal_protocol::Aci;
        match self.identity {
            ServiceIdType::AccountIdentity => {
                Some(Aci::from_uuid_bytes(self.uuid.into_bytes()))
            },
            ServiceIdType::PhoneNumberIdentity => None,
        }
    }

    pub fn pni(&self) -> Option<libsignal_protocol::Pni> {
        use libsignal_protocol::Pni;
        match self.identity {
            ServiceIdType::AccountIdentity => None,
            ServiceIdType::PhoneNumberIdentity => {
                Some(Pni::from_uuid_bytes(self.uuid.into_bytes()))
            },
        }
    }

    pub fn to_service_id(&self) -> String {
        match self.identity {
            ServiceIdType::AccountIdentity => self.uuid.to_string(),
            ServiceIdType::PhoneNumberIdentity => {
                format!("PNI:{}", self.uuid)
            },
        }
    }
}

impl TryFrom<&ProtocolAddress> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(addr: &ProtocolAddress) -> Result<Self, Self::Error> {
        let value = addr.name();
        if let Some(pni) = value.strip_prefix("PNI:") {
            Ok(ServiceAddress::new_pni(Uuid::parse_str(pni)?))
        } else {
            Ok(ServiceAddress::new_aci(Uuid::parse_str(value)?))
        }
        .map_err(|e| {
            tracing::error!("Parsing ServiceAddress from {:?}", addr);
            ParseServiceAddressError::InvalidUuid(e)
        })
    }
}

impl TryFrom<&str> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some(pni) = value.strip_prefix("PNI:") {
            Ok(ServiceAddress::new_pni(Uuid::parse_str(pni)?))
        } else {
            Ok(ServiceAddress::new_aci(Uuid::parse_str(value)?))
        }
        .map_err(|e| {
            tracing::error!("Parsing ServiceAddress from '{}'", value);
            ParseServiceAddressError::InvalidUuid(e)
        })
    }
}

impl TryFrom<&[u8]> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Some(pni) = value.strip_prefix(b"PNI:") {
            Ok(ServiceAddress::new_pni(Uuid::from_slice(pni)?))
        } else {
            Ok(ServiceAddress::new_aci(Uuid::from_slice(value)?))
        }
        .map_err(|e| {
            tracing::error!("Parsing ServiceAddress from {:?}", value);
            ParseServiceAddressError::InvalidUuid(e)
        })
    }
}
