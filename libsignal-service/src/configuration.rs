#[derive(Clone, Default)]
pub struct ServiceConfiguration {
    pub service_urls: Vec<String>,
    pub cdn_urls: Vec<String>,
    pub contact_discovery_url: Vec<String>,
}

pub struct Credentials {
    pub uuid: String,
    pub e164: String,
    pub password: String,
}
