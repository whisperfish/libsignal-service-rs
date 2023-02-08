use std::{convert::TryFrom, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{push_service::ServiceError, session_store::SessionStoreExt};

#[derive(thiserror::Error, Debug, Clone)]
pub enum ParseServiceAddressError {
    #[error("Supplied UUID could not be parsed")]
    InvalidUuidError(#[from] uuid::Error),

    #[error("Envelope with no Uuid")]
    NoSenderError,
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

impl ServiceAddress {
    pub async fn sub_device_sessions<S: SessionStoreExt>(
        &self,
        session_store: &S,
    ) -> Result<Vec<u32>, ServiceError> {
        let mut sub_device_sessions = Vec::new();
        sub_device_sessions.extend(
            session_store
                .get_sub_device_sessions(&self.uuid.to_string())
                .await?,
        );
        Ok(sub_device_sessions)
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
            Some(Err(e)) => Err(ParseServiceAddressError::InvalidUuidError(e)),
            None => Err(ParseServiceAddressError::NoSenderError),
        }
    }
}
