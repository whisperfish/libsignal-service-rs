use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
