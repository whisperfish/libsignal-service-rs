use std::{convert::TryFrom, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ParseServiceAddressError {
    #[error("Supplied UUID could not be parsed")]
    InvalidUuid(#[from] uuid::Error),

    #[error("Envelope with no Uuid")]
    NoUuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceAddress {
    pub uuid: Uuid,
}

impl fmt::Display for ServiceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uuid)
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
