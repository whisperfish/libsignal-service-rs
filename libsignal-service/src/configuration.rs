use std::{collections::HashMap, str::FromStr};

use libsignal_protocol::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;
use zkgroup::ServerPublicParams;

use crate::{
    envelope::{CIPHER_KEY_SIZE, MAC_KEY_SIZE},
    push_service::{HttpAuth, ServiceError, DEFAULT_DEVICE_ID},
    sealed_session_cipher::{CertificateValidator, SealedSessionError},
};

#[derive(Clone)]
pub struct ServiceConfiguration {
    service_url: Url,
    storage_url: Url,
    cdn_urls: HashMap<u32, Url>,
    contact_discovery_url: Url,
    pub certificate_authority: String,
    pub unidentified_sender_trust_root: String,
    pub zkgroup_server_public_params: ServerPublicParams,
}

pub type SignalingKey = [u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE];

#[derive(Clone)]
pub struct ServiceCredentials {
    pub uuid: Option<uuid::Uuid>,
    pub phonenumber: phonenumber::PhoneNumber,
    pub password: Option<String>,
    pub signaling_key: Option<SignalingKey>,
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

const SIGNAL_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEdMBsGA1UECgwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9wZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQDDApUZXh0U2VjdXJlMB4XDTEzMDMyNTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRPcGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxEzARBgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBSWBpOCBDF0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvfPo863i6Crq1KDxHpB36EwzVcjwLkFTIMeo7t9s1FQolAt3mErV2U0vie6Ves+yj6grSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADyps5B+Zmqcgf653TXS5/0IPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbteLtVgwBm9R5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4jb69vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjxP/s5GURuhYa+lGUypzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8kDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1RK6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pPOU6JjIxnrD1XD/EVmTTaTVY5iOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA1IMIo3J/s2WF/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en4DGXRaLMPRwjELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLErwLV
-----END CERTIFICATE-----"#;

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
                certificate_authority: SIGNAL_ROOT_CA.into(),
                unidentified_sender_trust_root:
                    "BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx".into(),
                zkgroup_server_public_params: bincode::deserialize(&base64::decode("ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdls=").unwrap()).unwrap(),
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
                certificate_authority: SIGNAL_ROOT_CA.into(),
                unidentified_sender_trust_root:
                    "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF".into(),
                zkgroup_server_public_params: bincode::deserialize(
                    &base64::decode("AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X0=").unwrap()).unwrap(),
            },
        }
    }
}

impl ServiceConfiguration {
    pub fn credentials_validator(
        &self,
    ) -> Result<CertificateValidator, ServiceError> {
        Ok(CertificateValidator::new(PublicKey::deserialize(
            &base64::decode(&self.unidentified_sender_trust_root)
                .map_err(|_| SealedSessionError::InvalidCertificate)?,
        )?))
    }

    pub fn base_url(&self, endpoint: Endpoint) -> &Url {
        match endpoint {
            Endpoint::Service => &self.service_url,
            Endpoint::Storage => &self.storage_url,
            Endpoint::Cdn(ref n) => &self.cdn_urls[n],
            Endpoint::ContactDiscovery => &self.contact_discovery_url,
        }
    }
}
