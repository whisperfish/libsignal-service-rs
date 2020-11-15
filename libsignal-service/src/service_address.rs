use phonenumber::*;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum ParseServiceAddressError {
    #[error("Supplied phone number could not be parsed")]
    InvalidE164Error(#[from] phonenumber::ParseError),

    #[error("Supplied uuid could not be parsed")]
    InvalidUuidError(#[from] uuid::Error),

    #[error("Envelope with neither Uuid or E164")]
    NoSenderError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAddress {
    pub uuid: Option<Uuid>,
    pub e164: Option<PhoneNumber>,
    pub relay: Option<String>,
}

impl std::fmt::Display for ServiceAddress {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> Result<(), std::fmt::Error> {
        match (&self.uuid, &self.e164, &self.relay) {
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
        let e164 = e164.map(|s| phonenumber::parse(None, s)).transpose()?;
        let uuid = uuid.map(Uuid::parse_str).transpose()?;

        Ok(ServiceAddress {
            e164,
            uuid,
            relay: None,
        })
    }

    /// Returns uuid if present, e164 otherwise.
    pub fn identifier(&self) -> String {
        if let Some(ref uuid) = self.uuid {
            return uuid.to_string();
        } else if let Some(ref e164) = self.e164 {
            return e164.format().mode(phonenumber::Mode::E164).to_string();
        }
        unreachable!(
            "an address requires either a UUID or a E164 phone number"
        );
    }

    pub fn matches(&self, other: &Self) -> bool {
        (self.e164.is_some() && self.e164 == other.e164)
            || (self.uuid.is_some() && self.uuid == other.uuid)
    }
}
