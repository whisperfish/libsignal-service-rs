use std::convert::TryFrom;

use libsignal_protocol::{DeviceId, ProtocolAddress};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ParseServiceAddressError {
    #[error("Supplied UUID could not be parsed")]
    InvalidUuid(#[from] uuid::Error),

    #[error("Envelope without UUID")]
    NoUuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceAddress {
    pub uuid: Uuid,
}

impl ServiceAddress {
    pub fn to_protocol_address(
        &self,
        device_id: impl Into<DeviceId>,
    ) -> ProtocolAddress {
        ProtocolAddress::new(self.uuid.to_string(), device_id.into())
    }

    pub fn aci(&self) -> libsignal_protocol::Aci {
        libsignal_protocol::Aci::from_uuid_bytes(self.uuid.into_bytes())
    }

    pub fn pni(&self) -> libsignal_protocol::Pni {
        libsignal_protocol::Pni::from_uuid_bytes(self.uuid.into_bytes())
    }
}

impl From<Uuid> for ServiceAddress {
    fn from(uuid: Uuid) -> Self {
        Self { uuid }
    }
}

impl TryFrom<&str> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(ServiceAddress {
            uuid: Uuid::parse_str(value)?,
        })
    }
}

impl TryFrom<Option<&str>> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: Option<&str>) -> Result<Self, Self::Error> {
        match value.map(Uuid::parse_str) {
            Some(Ok(uuid)) => Ok(ServiceAddress { uuid }),
            Some(Err(e)) => Err(ParseServiceAddressError::InvalidUuid(e)),
            None => Err(ParseServiceAddressError::NoUuid),
        }
    }
}

impl TryFrom<Option<&[u8]>> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: Option<&[u8]>) -> Result<Self, Self::Error> {
        match value.map(Uuid::from_slice) {
            Some(Ok(uuid)) => Ok(ServiceAddress { uuid }),
            Some(Err(e)) => Err(ParseServiceAddressError::InvalidUuid(e)),
            None => Err(ParseServiceAddressError::NoUuid),
        }
    }
}
