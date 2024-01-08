use std::{collections::HashMap, str::FromStr};

use libsignal_protocol::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;
use zkgroup::ServerPublicParams;

use crate::{
    envelope::{CIPHER_KEY_SIZE, MAC_KEY_SIZE},
    push_service::{HttpAuth, DEFAULT_DEVICE_ID},
};

#[derive(Clone)]
pub struct ServiceConfiguration {
    service_url: Url,
    storage_url: Url,
    cdn_urls: HashMap<u32, Url>,
    contact_discovery_url: Url,
    pub certificate_authority: String,
    pub unidentified_sender_trust_root: PublicKey,
    pub zkgroup_server_public_params: ServerPublicParams,
}

pub type SignalingKey = [u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE];

#[derive(Clone)]
pub struct ServiceCredentials {
    pub uuid: Option<uuid::Uuid>,
    pub phonenumber: phonenumber::PhoneNumber,
    pub password: Option<String>,
    pub device_id: Option<u32>,
}

impl ServiceCredentials {
    pub fn authorization(&self) -> Option<HttpAuth> {
        self.password.as_ref().map(|password| HttpAuth {
            username: self.login(),
            password: password.clone(),
        })
    }

    pub fn e164(&self) -> String {
        self.phonenumber
            .format()
            .mode(phonenumber::Mode::E164)
            .to_string()
    }

    pub fn login(&self) -> String {
        let identifier = {
            if let Some(uuid) = self.uuid.as_ref() {
                uuid.to_string()
            } else {
                self.e164()
            }
        };

        match self.device_id {
            None | Some(DEFAULT_DEVICE_ID) => identifier,
            Some(id) => format!("{}.{}", identifier, id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalServers {
    Staging,
    Production,
}

#[derive(Debug)]
pub enum Endpoint {
    Service,
    Storage,
    Cdn(u32),
    ContactDiscovery,
}

impl FromStr for SignalServers {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::io::ErrorKind;
        match s {
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(Self::Err::new(
                ErrorKind::InvalidInput,
                "invalid signal servers, can be either: staging or production",
            )),
        }
    }
}

impl ToString for SignalServers {
    fn to_string(&self) -> String {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
        .to_string()
    }
}

impl From<SignalServers> for ServiceConfiguration {
    fn from(val: SignalServers) -> Self {
        ServiceConfiguration::from(&val)
    }
}

impl From<&SignalServers> for ServiceConfiguration {
    fn from(val: &SignalServers) -> Self {
        // base configuration from https://github.com/signalapp/Signal-Desktop/blob/development/config/default.json
        match val {
            // configuration with the Signal API staging endpoints
            // see: https://github.com/signalapp/Signal-Desktop/blob/master/config/default.json
            SignalServers::Staging => ServiceConfiguration {
                service_url: "https://chat.staging.signal.org".parse().unwrap(),
                storage_url:"https://storage-staging.signal.org".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn-staging.signal.org".parse().unwrap());
                    map.insert(2, "https://cdn2-staging.signal.org".parse().unwrap());
                    map
                },
                contact_discovery_url:
                    "https://api-staging.directory.signal.org".parse().unwrap(),
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/staging-root-ca.pem")).to_string(),
                unidentified_sender_trust_root:
                    PublicKey::deserialize(&base64::decode("BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx").unwrap()).unwrap(),
                zkgroup_server_public_params: bincode::deserialize(&base64::decode("ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdlukrpzzsCIvEwjwQlJYVPOQPj4V0F4UXXBdHSLK05uoPBCQG8G9rYIGedYsClJXnbrgGYG3eMTG5hnx4X4ntARBgELuMWWUEEfSK0mjXg+/2lPmWcTZWR9nkqgQQP0tbzuiPm74H2wMO4u1Wafe+UwyIlIT9L7KLS19Aw8r4sPrXZSSsOZ6s7M1+rTJN0bI5CKY2PX29y5Ok3jSWufIKcgKOnWoP67d5b2du2ZVJjpjfibNIHbT/cegy/sBLoFwtHogVYUewANUAXIaMPyCLRArsKhfJ5wBtTminG/PAvuBdJ70Z/bXVPf8TVsR292zQ65xwvWTejROW6AZX6aqucUj").unwrap()).unwrap(),
            },
            // configuration with the Signal API production endpoints
            // https://github.com/signalapp/Signal-Desktop/blob/master/config/production.json
            SignalServers::Production => ServiceConfiguration {
                service_url:
                    "https://chat.signal.org".parse().unwrap(),
                storage_url: "https://storage.signal.org".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn.signal.org".parse().unwrap());
                    map.insert(2, "https://cdn2.signal.org".parse().unwrap());
                    map
                },
                contact_discovery_url: "https://api.directory.signal.org".parse().unwrap(),
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/production-root-ca.pem")).to_string(),
                unidentified_sender_trust_root:
                    PublicKey::deserialize(&base64::decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap()).unwrap(),
                zkgroup_server_public_params: bincode::deserialize(
                    &base64::decode("AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P").unwrap()).unwrap(),
            },
        }
    }
}

impl ServiceConfiguration {
    pub fn base_url(&self, endpoint: Endpoint) -> &Url {
        match endpoint {
            Endpoint::Service => &self.service_url,
            Endpoint::Storage => &self.storage_url,
            Endpoint::Cdn(ref n) => &self.cdn_urls[n],
            Endpoint::ContactDiscovery => &self.contact_discovery_url,
        }
    }
}
