use std::{collections::HashMap, str::FromStr};

use libsignal_protocol::{keys::PublicKey, Context};

use crate::{
    envelope::{CIPHER_KEY_SIZE, MAC_KEY_SIZE},
    push_service::{DEFAULT_DEVICE_ID, ServiceError},
    sealed_session_cipher::{CertificateValidator, SealedSessionError},
};

#[derive(Debug, Clone)]
pub struct ServiceConfiguration {
    pub service_urls: Vec<String>,
    pub cdn_urls: HashMap<u32, String>,
    pub contact_discovery_url: Vec<String>,
    pub certificate_authority: String,
    pub unidentified_sender_trust_root: String,
}

pub type SignalingKey = [u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE];

#[derive(Clone)]
pub struct Credentials {
    pub uuid: Option<String>,
    pub e164: String,
    pub password: Option<String>,
    pub signaling_key: Option<SignalingKey>,
    pub device_id: Option<i32>,
}

impl Credentials {
    /// Kind-of equivalent with `PushServiceSocket::getAuthorizationHeader`
    ///
    /// None when `self.password == None`
    pub fn authorization(&self) -> Option<(String, &str)> {
        let identifier = self.login();
        Some((identifier, self.password.as_ref()?))
    }

    pub fn login(&self) -> String {
        let identifier = {
            if let Some(uuid) = self.uuid.as_ref() {
                uuid
            } else {
                &self.e164
            }.to_owned()
        };

        match self.device_id {
            None | Some(DEFAULT_DEVICE_ID) => identifier,
            Some(id) => {
                identifier + "." + id.to_string().as_str()
            },
        }
    }
}

const SIGNAL_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIID7zCCAtegAwIBAgIJAIm6LatK5PNiMA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEdMBsGA1UECgwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxHTAbBgNVBAsMFE9wZW4gV2hpc3BlciBTeXN0ZW1zMRMwEQYDVQQDDApUZXh0U2VjdXJlMB4XDTEzMDMyNTIyMTgzNVoXDTIzMDMyMzIyMTgzNVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRPcGVuIFdoaXNwZXIgU3lzdGVtczEdMBsGA1UECwwUT3BlbiBXaGlzcGVyIFN5c3RlbXMxEzARBgNVBAMMClRleHRTZWN1cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBSWBpOCBDF0i4q2d4jAXkSXUGpbeWugVPQCjaL6qD9QDOxeW1afvfPo863i6Crq1KDxHpB36EwzVcjwLkFTIMeo7t9s1FQolAt3mErV2U0vie6Ves+yj6grSfxwIDAcdsKmI0a1SQCZlr3Q1tcHAkAKFRxYNawADyps5B+Zmqcgf653TXS5/0IPPQLocLn8GWLwOYNnYfBvILKDMItmZTtEbucdigxEA9mfIvvHADEbteLtVgwBm9R5vVvtwrD6CCxI3pgH7EH7kMP0Od93wLisvn1yhHY7FuYlrkYqdkMvWUrKoASVw4jb69vaeJCUdU+HCoXOSP1PQcL6WenNCHAgMBAAGjUDBOMB0GA1UdDgQWBBQBixjxP/s5GURuhYa+lGUypzI8kDAfBgNVHSMEGDAWgBQBixjxP/s5GURuhYa+lGUypzI8kDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQB+Hr4hC56m0LvJAu1RK6NuPDbTMEN7/jMojFHxH4P3XPFfupjR+bkDq0pPOU6JjIxnrD1XD/EVmTTaTVY5iOheyv7UzJOefb2pLOc9qsuvI4fnaESh9bhzln+LXxtCrRPGhkxA1IMIo3J/s2WF/KVYZyciu6b4ubJ91XPAuBNZwImug7/srWvbpk0hq6A6z140WTVSKtJG7EP41kJe/oF4usY5J7LPkxK3LWzMJnb5EIJDmRvyH8pyRwWg6Qm6qiGFaI4nL8QU4La1x2en4DGXRaLMPRwjELNgQPodR38zoCMuA8gHZfZYYoZ7D7Q1wNUiVHcxuFrEeBaYJbLErwLV
-----END CERTIFICATE-----"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalServers {
    Staging,
    Production,
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

impl Into<ServiceConfiguration> for SignalServers {
    fn into(self) -> ServiceConfiguration {
        // base configuration from https://github.com/signalapp/Signal-Desktop/blob/development/config/default.json
        match self {
            // configuration with the Signal API staging endpoints
            // see: https://github.com/signalapp/Signal-Desktop/blob/master/config/default.json
            SignalServers::Staging => ServiceConfiguration {
                service_urls: vec![
                    "https://textsecure-service-staging.whispersystems.org"
                        .into(),
                ],
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn-staging.signal.org".into());
                    map.insert(2, "https://cdn2-staging.signal.org".into());
                    map
                },
                contact_discovery_url: vec![
                    "https://api-staging.directory.signal.org".into(),
                ],
                certificate_authority: SIGNAL_ROOT_CA.into(),
                unidentified_sender_trust_root:
                    "BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx".into(),
            },
            // configuration with the Signal API production endpoints
            // https://github.com/signalapp/Signal-Desktop/blob/master/config/production.json
            SignalServers::Production => ServiceConfiguration {
                service_urls: vec![
                    "https://textsecure-service.whispersystems.org".into(),
                ],
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn.signal.org".into());
                    map.insert(2, "https://cdn2.signal.org".into());
                    map
                },
                contact_discovery_url: vec![
                    "https://api.directory.signal.org".into()
                ],
                certificate_authority: SIGNAL_ROOT_CA.into(),
                unidentified_sender_trust_root:
                    "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF".into(),
            },
        }
    }
}

impl ServiceConfiguration {
    pub fn credentials_validator(
        &self,
        context: &Context,
    ) -> Result<CertificateValidator, ServiceError> {
        Ok(CertificateValidator::new(PublicKey::decode_point(
            context,
            &base64::decode(&self.unidentified_sender_trust_root)
                .map_err(|_| SealedSessionError::InvalidCertificate)?,
        )?))
    }
}
