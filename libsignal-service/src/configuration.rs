#[derive(Clone, Default)]
pub struct ServiceConfiguration {
    pub service_urls: Vec<String>,
    pub cdn_urls: Vec<String>,
    pub contact_discovery_url: Vec<String>,
}

pub trait CredentialsProvider {
    fn get_uuid(&self) -> String;

    fn get_e164(&self) -> String;

    fn get_password(&self) -> String;
}

pub struct StaticCredentialsProvider {
    pub uuid: String,
    pub e164: String,
    pub password: String,
}

impl CredentialsProvider for StaticCredentialsProvider {
    fn get_uuid(&self) -> String { self.uuid.clone() }

    fn get_e164(&self) -> String { self.e164.clone() }

    fn get_password(&self) -> String { self.password.clone() }
}
