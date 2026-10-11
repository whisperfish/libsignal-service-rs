use std::{sync::LazyLock, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials, SignalServers},
    prelude::ServiceConfiguration,
    utils::{serde_device_id_vec, serde_service_id_vec},
    websocket::{SignalWebSocket, WebSocketType},
};

use libsignal_core::DeviceId;
use libsignal_protocol::ServiceId;
use protobuf::ProtobufResponseExt;
use reqwest::{Method, RequestBuilder};
use reqwest_websocket::Upgrade;
use serde::{Deserialize, Serialize};
use tracing::{debug_span, Instrument};

pub const KEEPALIVE_TIMEOUT_SECONDS: Duration = Duration::from_secs(55);
pub static DEFAULT_DEVICE_ID: LazyLock<libsignal_core::DeviceId> =
    LazyLock::new(|| libsignal_core::DeviceId::try_from(1).unwrap());

mod account;
mod cdn;
mod error;
pub mod linking;
pub(crate) mod response;

pub use account::*;
pub use cdn::*;
pub use error::*;
pub(crate) use response::SignalServiceResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofRequired {
    pub token: String,
    pub options: Vec<String>,
}

#[derive(derive_more::Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuth {
    pub username: String,
    #[debug(ignore)]
    pub password: String,
}

#[derive(Debug, Clone)]
pub enum HttpAuthOverride {
    NoOverride,
    Unidentified,
    Identified(HttpAuth),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AvatarWrite<C> {
    NewAvatar(C),
    RetainAvatar,
    NoAvatar,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MismatchedDevices {
    #[serde(with = "serde_device_id_vec")]
    pub missing_devices: Vec<DeviceId>,
    #[serde(with = "serde_device_id_vec")]
    pub extra_devices: Vec<DeviceId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDevices {
    #[serde(with = "serde_device_id_vec")]
    pub stale_devices: Vec<DeviceId>,
}

/// `PUT /v1/messages/multi_recipient` success response.
///
/// Mirrors `SendMultiRecipientMessageResponse` on the server: the service
/// identifiers in the request that do not correspond to registered users. Only
/// populated when a group send endorsement token was supplied.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMultiRecipientMessageResponse {
    #[serde(default, with = "serde_service_id_vec")]
    pub uuids404: Vec<ServiceId>,
}

#[derive(Clone)]
pub struct PushService {
    pub(crate) servers: SignalServers,
    cfg: ServiceConfiguration,
    credentials: Option<HttpAuth>,
    client: reqwest::Client,
}

impl PushService {
    pub fn new(
        env: SignalServers,
        credentials: Option<ServiceCredentials>,
        user_agent: impl AsRef<str>,
    ) -> Self {
        let cfg: ServiceConfiguration = env.into();

        // Use the ring provider except if the application already installed one.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        let client = reqwest::ClientBuilder::new()
            .tls_certs_only([reqwest::Certificate::from_pem(
                cfg.certificate_authority.as_bytes(),
            )
            .unwrap()])
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(65))
            .user_agent(user_agent.as_ref())
            .http1_only()
            .build()
            .unwrap();

        Self {
            servers: env,
            cfg,
            credentials: credentials.and_then(|c| c.authorization()),
            client,
        }
    }

    #[tracing::instrument(skip(self), fields(endpoint = %endpoint))]
    pub fn request(
        &self,
        method: Method,
        endpoint: Endpoint,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder, ServiceError> {
        let url = endpoint.into_url(&self.cfg)?;
        let mut builder = self.client.request(method, url);

        builder = match auth_override {
            HttpAuthOverride::NoOverride => {
                if let Some(HttpAuth { username, password }) =
                    self.credentials.as_ref()
                {
                    builder.basic_auth(username, Some(password))
                } else {
                    builder
                }
            },
            HttpAuthOverride::Identified(HttpAuth { username, password }) => {
                builder.basic_auth(username, Some(password))
            },
            HttpAuthOverride::Unidentified => builder,
        };

        Ok(builder)
    }

    pub async fn ws<C: WebSocketType>(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket<C>, ServiceError> {
        let span = debug_span!("websocket");

        let mut url = Endpoint::service(path).into_url(&self.cfg)?;
        url.set_scheme("wss").expect("valid https base url");

        let mut builder = self.client.get(url);
        for (key, value) in additional_headers {
            builder = builder.header(*key, *value);
        }

        if let Some(credentials) = credentials {
            builder =
                builder.basic_auth(credentials.login(), credentials.password);
        }

        let ws = builder
            .upgrade()
            .send()
            .await?
            .into_websocket()
            .instrument(span.clone())
            .await?;

        let unidentified_push_service = PushService {
            servers: self.servers,
            cfg: self.cfg.clone(),
            credentials: None,
            client: self.client.clone(),
        };
        let (ws, task) = SignalWebSocket::new(
            ws,
            keepalive_path.to_owned(),
            unidentified_push_service,
        );
        let task = task.instrument(span);
        tokio::task::spawn(task);
        Ok(ws)
    }

    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<crate::proto::Group, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::storage("/v1/groups/"),
            HttpAuthOverride::Identified(credentials),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .protobuf()
        .await
    }
}

pub(crate) mod protobuf {
    use async_trait::async_trait;
    use prost::{EncodeError, Message};
    use reqwest::{header, RequestBuilder, Response};

    use super::ServiceError;

    pub(crate) trait ProtobufRequestBuilderExt
    where
        Self: Sized,
    {
        /// Set the request payload encoded as protobuf.
        /// Sets the `Content-Type` header to `application/x-protobuf`
        #[allow(dead_code)]
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError>;
    }

    #[async_trait::async_trait]
    pub(crate) trait ProtobufResponseExt {
        /// Get the response body decoded from Protobuf
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: prost::Message + Default;
    }

    impl ProtobufRequestBuilderExt for RequestBuilder {
        fn protobuf<T: Message + Default>(
            self,
            value: T,
        ) -> Result<Self, EncodeError> {
            let mut buf = Vec::new();
            value.encode(&mut buf)?;
            let this =
                self.header(header::CONTENT_TYPE, "application/x-protobuf");
            Ok(this.body(buf))
        }
    }

    #[async_trait]
    impl ProtobufResponseExt for Response {
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: Message + Default,
        {
            let body = self.bytes().await?;
            let decoded = T::decode(body)?;
            Ok(decoded)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::SignalServers;
    use bytes::{Buf, Bytes};

    #[test]
    fn create_clients() {
        let environments = &[SignalServers::Staging, SignalServers::Production];

        for env in environments {
            let _ =
                super::PushService::new(*env, None, "libsignal-service test");
        }
    }

    #[test]
    fn serde_json_from_empty_reader() {
        // This fails, so we have handle empty response body separately in HyperPushService::json()
        let bytes: Bytes = "".into();
        assert!(
            serde_json::from_reader::<bytes::buf::Reader<Bytes>, String>(
                bytes.reader()
            )
            .is_err()
        );
    }

    #[test]
    fn serde_json_form_empty_vec() {
        // If we're trying to send and empty payload, serde_json must be able to make a Vec out of it
        assert!(serde_json::to_vec(b"").is_ok());
    }

    #[test]
    fn multi_recipient_response_decodes_uuids404() {
        use super::{
            AccountMismatchedDevices, AccountStaleDevices,
            SendMultiRecipientMessageResponse,
        };
        use libsignal_protocol::{Aci, ServiceId};

        // Stories: no uuids404 array is sent.
        let story: SendMultiRecipientMessageResponse =
            serde_json::from_str("{}").unwrap();
        assert!(story.uuids404.is_empty());

        let aci = Aci::from(uuid::Uuid::nil());
        let pni = libsignal_protocol::Pni::from(uuid::Uuid::from_u128(
            0x1234_5678_1234_5678_1234_5678_1234_5678,
        ));
        let json = format!(
            r#"{{"uuids404":["{}","{}"]}}"#,
            aci.service_id_string(),
            pni.service_id_string()
        );
        let resp: SendMultiRecipientMessageResponse =
            serde_json::from_str(&json).unwrap();
        assert_eq!(resp.uuids404.len(), 2);
        assert_eq!(resp.uuids404[0], ServiceId::Aci(aci));
        assert_eq!(resp.uuids404[1], ServiceId::Pni(pni));

        // 409 / 410 bodies carry the same per-recipient sub-shape as the 1:1
        // endpoints, wrapped per-account.
        let mismatched: Vec<AccountMismatchedDevices> = serde_json::from_str(
            &format!(
                r#"[{{"uuid":"{}","devices":{{"missingDevices":[1,2],"extraDevices":[3]}}}}]"#,
                aci.service_id_string()
            ),
        )
        .unwrap();
        assert_eq!(mismatched.len(), 1);
        assert_eq!(mismatched[0].uuid, ServiceId::Aci(aci));
        assert_eq!(mismatched[0].devices.missing_devices.len(), 2);
        assert_eq!(mismatched[0].devices.extra_devices.len(), 1);

        let stale: Vec<AccountStaleDevices> = serde_json::from_str(&format!(
            r#"[{{"uuid":"{}","devices":{{"staleDevices":[5]}}}}]"#,
            aci.service_id_string()
        ))
        .unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].devices.stale_devices.len(), 1);
    }
}
