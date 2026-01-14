use core::fmt;
use std::{borrow::Cow, collections::HashMap, str::FromStr};

use crate::utils::BASE64_RELAXED;
use base64::prelude::*;
use libsignal_core::DeviceId;
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
    pub unidentified_sender_trust_roots: Vec<PublicKey>,
    pub zkgroup_server_public_params: ServerPublicParams,
}

pub type SignalingKey = [u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE];

#[derive(Clone)]
pub struct ServiceCredentials {
    pub aci: Option<uuid::Uuid>,
    pub pni: Option<uuid::Uuid>,
    pub phonenumber: phonenumber::PhoneNumber,
    pub password: Option<String>,
    pub signaling_key: Option<SignalingKey>,
    pub device_id: Option<DeviceId>,
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
            if let Some(uuid) = self.aci.as_ref() {
                uuid.to_string()
            } else {
                self.e164()
            }
        };

        match self.device_id {
            None => identifier,
            Some(device_id) if device_id == *DEFAULT_DEVICE_ID => identifier,
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
pub enum Endpoint<'a> {
    Absolute(Url),
    Service {
        path: Cow<'a, str>,
    },
    Storage {
        path: Cow<'a, str>,
    },
    Cdn {
        cdn_id: u32,
        path: Cow<'a, str>,
        query: Option<Cow<'a, str>>,
    },
    ContactDiscovery {
        path: Cow<'a, str>,
    },
}

impl fmt::Display for Endpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Absolute(url) => write!(f, "absolute URL {url}"),
            Endpoint::Service { path } => {
                write!(f, "service API call to {path}")
            },
            Endpoint::Storage { path } => {
                write!(f, "storage API call to {path}")
            },
            Endpoint::Cdn { cdn_id, path, .. } => {
                write!(f, "CDN{cdn_id} call to {path}")
            },
            Endpoint::ContactDiscovery { path } => {
                write!(f, "Contact discovery API call to {path}")
            },
        }
    }
}

impl<'a> Endpoint<'a> {
    pub fn service(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Service { path: path.into() }
    }

    pub fn cdn(cdn_id: u32, path: impl Into<Cow<'a, str>>) -> Self {
        Self::Cdn {
            cdn_id,
            path: path.into(),
            query: None,
        }
    }

    pub fn cdn_url(cdn_id: u32, url: &'a Url) -> Self {
        Self::Cdn {
            cdn_id,
            path: url.path().into(),
            query: url.query().map(Into::into),
        }
    }

    pub fn storage(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Storage { path: path.into() }
    }

    pub fn into_url(
        self,
        service_configuration: &ServiceConfiguration,
    ) -> Result<Url, url::ParseError> {
        match self {
            Endpoint::Service { path } => {
                service_configuration.service_url.join(&path)
            },
            Endpoint::Storage { path } => {
                service_configuration.storage_url.join(&path)
            },
            Endpoint::Cdn {
                ref cdn_id,
                path,
                query,
            } => {
                let mut url = service_configuration.cdn_urls[cdn_id].clone();
                url.set_path(&path);
                url.set_query(query.as_deref());
                Ok(url)
            },
            Endpoint::ContactDiscovery { path } => {
                service_configuration.contact_discovery_url.join(&path)
            },
            Endpoint::Absolute(url) => Ok(url),
        }
    }
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

impl fmt::Display for SignalServers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staging => f.write_str("staging"),
            Self::Production => f.write_str("production"),
        }
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
                    map.insert(3, "https://cdn3-staging.signal.org".parse().unwrap());
                    map
                },
                contact_discovery_url:
                    "https://api-staging.directory.signal.org".parse().unwrap(),
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/staging-root-ca.pem")).to_string(),
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx").unwrap()).unwrap(),
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BYhU6tPjqP46KGZEzRs1OL4U39V5dlPJ/X09ha4rErkm").unwrap()).unwrap(),
                ],
                zkgroup_server_public_params: bincode::deserialize(&BASE64_RELAXED.decode("ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdlukrpzzsCIvEwjwQlJYVPOQPj4V0F4UXXBdHSLK05uoPBCQG8G9rYIGedYsClJXnbrgGYG3eMTG5hnx4X4ntARBgELuMWWUEEfSK0mjXg+/2lPmWcTZWR9nkqgQQP0tbzuiPm74H2wMO4u1Wafe+UwyIlIT9L7KLS19Aw8r4sPrXZSSsOZ6s7M1+rTJN0bI5CKY2PX29y5Ok3jSWufIKcgKOnWoP67d5b2du2ZVJjpjfibNIHbT/cegy/sBLoFwtHogVYUewANUAXIaMPyCLRArsKhfJ5wBtTminG/PAvuBdJ70Z/bXVPf8TVsR292zQ65xwvWTejROW6AZX6aqucUjlENAErBme1YHmOSpU6tr6doJ66dPzVAWIanmO/5mgjNEDeK7DDqQdB1xd03HT2Qs2TxY3kCK8aAb/0iM0HQiXjxZ9HIgYhbtvGEnDKW5ILSUydqH/KBhW4Pb0jZWnqN/YgbWDKeJxnDbYcUob5ZY5Lt5ZCMKuaGUvCJRrCtuugSMaqjowCGRempsDdJEt+cMaalhZ6gczklJB/IbdwENW9KeVFPoFNFzhxWUIS5ML9riVYhAtE6JE5jX0xiHNVIIPthb458cfA8daR0nYfYAUKogQArm0iBezOO+mPk5vCNWI+wwkyFCqNDXz/qxl1gAntuCJtSfq9OC3NkdhQlgYQ==").unwrap()).unwrap(),
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
                    map.insert(3, "https://cdn3.signal.org".parse().unwrap());
                    map
                },
                contact_discovery_url: "https://api.directory.signal.org".parse().unwrap(),
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/production-root-ca.pem")).to_string(),
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap()).unwrap(),
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6").unwrap()).unwrap(),
                ],
                zkgroup_server_public_params: bincode::deserialize(
                    &BASE64_RELAXED.decode("AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==").unwrap()).unwrap(),
            },
        }
    }
}
