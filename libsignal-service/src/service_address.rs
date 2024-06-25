use std::convert::TryFrom;

use libsignal_protocol::{DeviceId, ProtocolAddress};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::push_service::ServiceIdType;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ParseServiceAddressError {
    #[error("Supplied UUID could not be parsed")]
    InvalidUuid(#[from] uuid::Error),

    #[error("Envelope without UUID")]
    NoUuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
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

impl From<Uuid> for ServiceAddress {
    fn from(uuid: Uuid) -> Self {
        Self {
            uuid,
            identity: ServiceIdType::AccountIdentity,
        }
    }
}

impl TryFrom<&ProtocolAddress> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(addr: &ProtocolAddress) -> Result<Self, Self::Error> {
        let value = addr.name();
        if let Some(pni) = value.strip_prefix("PNI:") {
            Ok(ServiceAddress {
                uuid: Uuid::parse_str(pni)?,
                identity: ServiceIdType::PhoneNumberIdentity,
            })
        } else {
            match Uuid::parse_str(value) {
                Ok(uuid) => Ok(ServiceAddress {
                    uuid,
                    identity: ServiceIdType::AccountIdentity,
                }),
                Err(e) => {
                    tracing::error!("Unknown identity format: {}", value);
                    Err(ParseServiceAddressError::InvalidUuid(e))
                },
            }
        }
    }
}

impl TryFrom<&str> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.starts_with("PNI:") {
            Ok(ServiceAddress {
                uuid: Uuid::parse_str(value.strip_prefix("PNI:").unwrap())?,
                identity: ServiceIdType::PhoneNumberIdentity,
            })
        } else {
            Ok(ServiceAddress {
                uuid: Uuid::parse_str(value)?,
                identity: ServiceIdType::AccountIdentity,
            })
        }
    }
}

impl TryFrom<&[u8]> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if let Some(pni) = value.strip_prefix(b"PNI:") {
            Ok(ServiceAddress {
                uuid: Uuid::from_slice(pni)?,
                identity: ServiceIdType::PhoneNumberIdentity,
            })
        } else {
            Ok(ServiceAddress {
                uuid: Uuid::from_slice(value)?,
                identity: ServiceIdType::AccountIdentity,
            })
        }
    }
}
