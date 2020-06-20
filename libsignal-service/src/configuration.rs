#[derive(Clone, Default)]
pub struct ServiceConfiguration {
    pub service_urls: Vec<String>,
    pub cdn_urls: Vec<String>,
    pub contact_discovery_url: Vec<String>,
}

pub struct Credentials {
    pub uuid: Option<String>,
    pub e164: String,
    pub password: Option<String>,
}

impl Credentials {
    /// Kind-of equivalent with `PushServiceSocket::getAuthorizationHeader`
    ///
    /// None when `self.password == None`
    pub fn authorization(&self) -> Option<(&str, &str)> {
        let identifier: &str = if let Some(uuid) = self.uuid.as_ref() {
            uuid
        } else {
            &self.e164
        };
        Some((identifier, self.password.as_ref()?))
    }
}
