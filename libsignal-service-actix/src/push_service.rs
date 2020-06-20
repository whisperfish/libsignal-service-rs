use libsignal_service::{configuration::*, push_service::*};

pub struct AwcPushService {
    client: awc::Client,
}

#[async_trait::async_trait(?Send)]
impl PushService for AwcPushService {
    async fn get(&mut self, _path: &str) -> Result<(), ServiceError> { Ok(()) }
}

impl AwcPushService {
    pub fn new(
        _cfg: ServiceConfiguration,
        _credentials: Credentials,
        user_agent: &str,
    ) -> Self {
        Self {
            client: awc::ClientBuilder::new()
                .header("X-Signal-Agent", user_agent)
                .finish(),
        }
    }
}
