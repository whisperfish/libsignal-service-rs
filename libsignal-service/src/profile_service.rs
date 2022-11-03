use crate::{
    proto::WebSocketRequestMessage,
    push_service::{ServiceError, SignalServiceProfile},
    websocket::SignalWebSocket,
    ServiceAddress,
};

pub struct ProfileService {
    ws: SignalWebSocket,
}

impl ProfileService {
    pub fn from_socket(ws: SignalWebSocket) -> Self {
        ProfileService { ws }
    }

    pub async fn retrieve_profile_by_id(
        &mut self,
        address: ServiceAddress,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let endpoint = match (profile_key, address.uuid) {
            (Some(key), Some(uuid)) => {
                let uid_bytes = uuid.as_bytes();
                let version = bincode::serialize(
                    &key.get_profile_key_version(*uid_bytes),
                )?;
                let version = std::str::from_utf8(&version)
                    .expect("hex encoded profile key version");
                format!("/v1/profile/{}/{}", uuid, version)
            },
            (_, _) => {
                format!("/v1/profile/{}", address.identifier())
            },
        };

        let request = WebSocketRequestMessage {
            path: Some(endpoint),
            verb: Some("GET".into()),
            // TODO: set locale to en_US
            ..Default::default()
        };

        self.ws.request_json(request).await
    }
}
