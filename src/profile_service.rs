use libsignal_protocol::ServiceId;

use crate::{
    proto::WebSocketRequestMessage,
    push_service::{ServiceError, ServiceIdType, SignalServiceProfile},
    websocket::SignalWebSocket,
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
        address: ServiceId,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let endpoint = match (profile_key, address) {
            (Some(key), ServiceId::Aci(aci)) => {
                let version =
                    bincode::serialize(&key.get_profile_key_version(aci))?;
                let version = std::str::from_utf8(&version)
                    .expect("hex encoded profile key version");
                format!("/v1/profile/{}/{}", address.raw_uuid(), version)
            },
            (Some(_), ServiceId::Pni(_)) => {
                return Err(ServiceError::InvalidAddressType(
                    ServiceIdType::PhoneNumberIdentity,
                ))
            },
            (None, _) => {
                format!("/v1/profile/{}", address.raw_uuid())
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
