use crate::envelope::{CIPHER_KEY_SIZE, MAC_KEY_SIZE};

#[derive(Clone, Default)]
pub struct ServiceConfiguration {
    pub service_urls: Vec<String>,
    pub cdn_urls: Vec<String>,
    pub contact_discovery_url: Vec<String>,
}

#[derive(Clone)]
pub struct Credentials {
    pub uuid: Option<String>,
    pub e164: String,
    pub password: Option<String>,

    pub signaling_key: [u8; CIPHER_KEY_SIZE + MAC_KEY_SIZE],
}

impl Credentials {
    /// Kind-of equivalent with `PushServiceSocket::getAuthorizationHeader`
    ///
    /// None when `self.password == None`
    pub fn authorization(&self) -> Option<(&str, &str)> {
        let identifier = self.login();
        Some((identifier, self.password.as_ref()?))
    }

    pub fn login(&self) -> &str {
        if let Some(uuid) = self.uuid.as_ref() {
            uuid
        } else {
            &self.e164
        }
    }
}
