use reqwest::Method;

use crate::{
    configuration::Endpoint,
    prelude::PushService,
    push_service::{
        HttpAuthOverride, ReqwestExt, ServiceError, SignalServiceProfile,
    },
    ServiceAddress,
};

pub struct ProfileService {
    push_service: PushService,
}

impl ProfileService {
    pub fn from_socket(push_service: PushService) -> Self {
        ProfileService { push_service }
    }

    pub async fn retrieve_profile_by_id(
        &mut self,
        address: ServiceAddress,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let path = match profile_key {
            Some(key) => {
                let version =
                    bincode::serialize(&key.get_profile_key_version(
                        address.aci().expect("profile by ACI ProtocolAddress"),
                    ))?;
                let version = std::str::from_utf8(&version)
                    .expect("hex encoded profile key version");
                format!("/v1/profile/{}/{}", address.uuid, version)
            },
            None => {
                format!("/v1/profile/{}", address.uuid)
            },
        };

        self.push_service
            .request(
                Method::GET,
                Endpoint::service(path),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
            .map_err(Into::into)
    }
}
