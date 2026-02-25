use std::{sync::LazyLock, time::Duration};

use crate::{
    configuration::{Endpoint, ServiceCredentials, SignalServers},
    prelude::ServiceConfiguration,
    utils::serde_device_id_vec,
    websocket::{SignalWebSocket, WebSocketType},
};

use libsignal_core::DeviceId;
use prost::Message;
use protobuf::ProtobufResponseExt;
use reqwest::{Method, RequestBuilder};
use reqwest_websocket::RequestBuilderExt;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

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
pub(crate) use response::{GroupServiceExt, ReqwestExt, SignalServiceResponse};

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
        let client = reqwest::ClientBuilder::new()
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    cfg.certificate_authority.as_bytes(),
                )
                .unwrap(),
            )
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

    #[tracing::instrument(skip(self, additional_headers, credentials))]
    pub async fn ws<C: WebSocketType>(
        &mut self,
        path: &str,
        keepalive_path: &str,
        additional_headers: &[(&'static str, &str)],
        credentials: Option<ServiceCredentials>,
    ) -> Result<SignalWebSocket<C>, ServiceError> {
        let span = tracing::debug_span!("websocket");

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
}

/// Response data from group operations that includes endorsement information.
#[derive(Debug)]
pub struct GroupResponseData {
    /// The decrypted group state.
    pub group: crate::proto::Group,
    /// Raw group send endorsements response bytes, if present.
    pub group_send_endorsements_response: Option<Vec<u8>>,
}

impl From<crate::proto::GroupResponse> for GroupResponseData {
    fn from(response: crate::proto::GroupResponse) -> Self {
        Self {
            group: response.group.unwrap_or_default(),
            group_send_endorsements_response: if response
                .group_send_endorsements_response
                .is_empty()
            {
                None
            } else {
                Some(response.group_send_endorsements_response)
            },
        }
    }
}

/// Response from group modification operations.
#[derive(Debug)]
pub struct GroupChangeResponseData {
    /// The group change returned by the server.
    pub group_change: crate::proto::GroupChange,
    /// Raw group send endorsements response bytes, if present.
    pub group_send_endorsements_response: Option<Vec<u8>>,
}

impl From<crate::proto::GroupChangeResponse> for GroupChangeResponseData {
    fn from(response: crate::proto::GroupChangeResponse) -> Self {
        Self {
            group_change: response.group_change.unwrap_or_default(),
            group_send_endorsements_response: if response
                .group_send_endorsements_response
                .is_empty()
            {
                None
            } else {
                Some(response.group_send_endorsements_response)
            },
        }
    }
}

/// Options for fetching group history logs.
#[derive(Debug, Clone)]
pub struct GroupLogOptions {
    /// The version to start fetching from.
    pub start_version: u32,
    /// Whether to include the full group state at the start version.
    pub include_first_state: bool,
    /// Whether to include the full group state at the latest version.
    pub include_last_state: bool,
    /// The maximum change epoch this client understands.
    pub max_supported_change_epoch: u32,
    /// If Some, send the cached endorsement expiration timestamp. If the server
    /// has newer endorsements, it will include them in the response. Send 0 or
    /// None to always receive endorsements.
    pub cached_endorsements_expiration: Option<u64>,
}

/// Response from the group log endpoint.
#[derive(Debug)]
pub struct GroupLogResponseData {
    /// The group changes, possibly paginated.
    pub changes: crate::proto::GroupChanges,
    /// Endorsements for the group, if the server has newer ones than cached.
    pub group_send_endorsements_response: Option<Vec<u8>>,
    /// Whether the response is paginated (206 Partial Content).
    pub paginated: bool,
    /// For paginated responses, the range of versions included (from Content-Range header).
    /// Format: (start_version, end_version).
    pub page_range: Option<(u32, u32)>,
    /// For paginated responses, the current server revision (from Content-Range header).
    pub current_revision: Option<u32>,
}

impl PushService {
    #[tracing::instrument(skip(self, credentials))]
    pub(crate) async fn get_group(
        &mut self,
        credentials: HttpAuth,
    ) -> Result<GroupResponseData, ServiceError> {
        let response: crate::proto::GroupResponse = self
            .request(
                Method::GET,
                Endpoint::storage("/v2/groups/"),
                HttpAuthOverride::Identified(credentials),
            )?
            .send()
            .await?
            .service_error_for_group_status()
            .await?
            .protobuf()
            .await?;
        Ok(response.into())
    }

    #[tracing::instrument(skip(self, credentials, group))]
    pub(crate) async fn create_group(
        &mut self,
        credentials: HttpAuth,
        group: crate::proto::Group,
    ) -> Result<GroupResponseData, ServiceError> {
        use protobuf::ProtobufRequestBuilderExt;
        let response: crate::proto::GroupResponse = self
            .request(
                Method::PUT,
                Endpoint::storage("/v2/groups/"),
                HttpAuthOverride::Identified(credentials),
            )?
            .protobuf(group)
            .send()
            .await?
            .service_error_for_group_status()
            .await?
            .protobuf()
            .await?;
        Ok(response.into())
    }

    #[tracing::instrument(
        skip(self, credentials, actions),
        fields(
            revision = actions.revision,
            add_members = actions.add_members.len()
        )
    )]
    pub(crate) async fn modify_group(
        &mut self,
        credentials: HttpAuth,
        actions: crate::proto::group_change::Actions,
    ) -> Result<GroupChangeResponseData, ServiceError> {
        use protobuf::ProtobufRequestBuilderExt;

        let response = self
            .request(
                Method::PATCH,
                Endpoint::storage("/v2/groups/"),
                HttpAuthOverride::Identified(credentials),
            )?
            .protobuf(actions)
            .send()
            .await?
            .service_error_for_group_status()
            .await?;

        let proto_response: crate::proto::GroupChangeResponse =
            response.protobuf().await?;
        Ok(proto_response.into())
    }

    /// Fetch group change history from the server.
    ///
    /// Uses the `/v2/groups/logs/{startVersion}` endpoint. Supports pagination via
    /// Content-Range header parsing and endorsement caching via the
    /// Cached-Send-Endorsements header.
    ///
    /// TODO: This method will be used for caching endorsements from group logs
    /// in a future implementation. See Group Send Endorsements specification.
    #[allow(dead_code)]
    #[tracing::instrument(
        skip(self, credentials, options),
        fields(
            start_version = options.start_version,
            include_first_state = options.include_first_state,
            include_last_state = options.include_last_state,
            max_supported_change_epoch = options.max_supported_change_epoch
        )
    )]
    pub(crate) async fn get_group_log(
        &mut self,
        credentials: HttpAuth,
        options: GroupLogOptions,
    ) -> Result<GroupLogResponseData, ServiceError> {
        let path = format!(
            "/v2/groups/logs/{}?includeFirstState={}&includeLastState={}&maxSupportedChangeEpoch={}",
            options.start_version,
            options.include_first_state,
            options.include_last_state,
            options.max_supported_change_epoch,
        );

        let mut request = self.request(
            Method::GET,
            Endpoint::storage(&path),
            HttpAuthOverride::Identified(credentials),
        )?;

        // Add endorsement caching header
        if let Some(expiration) = options.cached_endorsements_expiration {
            request = request
                .header("Cached-Send-Endorsements", expiration.to_string());
        }

        let response = request.send().await?;
        let status = response.status();

        // Parse Content-Range header for pagination info
        // Format: "versions {start}-{end}/{total}"
        let (paginated, page_range, current_revision) = if status.as_u16()
            == 206
        {
            if let Some(range_header) = response.headers().get("content-range")
            {
                if let Ok(range_str) = range_header.to_str() {
                    // Parse "versions 10-20/100"
                    static RANGE_REGEX: std::sync::LazyLock<regex::Regex> =
                        std::sync::LazyLock::new(|| {
                            regex::Regex::new(r"^versions\s+(\d+)-(\d+)/(\d+)$")
                                .unwrap()
                        });
                    if let Some(captures) = RANGE_REGEX.captures(range_str) {
                        (
                            true,
                            Some((
                                captures[1].parse().unwrap_or(0),
                                captures[2].parse().unwrap_or(0),
                            )),
                            Some(captures[3].parse().unwrap_or(0)),
                        )
                    } else {
                        (true, None, None)
                    }
                } else {
                    (true, None, None)
                }
            } else {
                (true, None, None)
            }
        } else {
            (false, None, None)
        };

        let response = response.service_error_for_group_status().await?;
        let bytes = response.bytes().await?;
        let changes = crate::proto::GroupChanges::decode(bytes.as_ref())?;

        let group_send_endorsements_response =
            if changes.group_send_endorsements_response.is_empty() {
                None
            } else {
                Some(changes.group_send_endorsements_response.clone())
            };

        Ok(GroupLogResponseData {
            changes,
            group_send_endorsements_response,
            paginated,
            page_range,
            current_revision,
        })
    }
}

pub(crate) mod protobuf {
    use async_trait::async_trait;
    use prost::Message;
    use reqwest::{header, RequestBuilder, Response};

    use super::ServiceError;

    pub(crate) trait ProtobufRequestBuilderExt
    where
        Self: Sized,
    {
        /// Set the request payload encoded as protobuf.
        /// Sets the `Content-Type` header to `application/x-protobuf`
        #[allow(dead_code)]
        fn protobuf<T: Message + Default>(self, value: T) -> Self;
    }

    impl ProtobufRequestBuilderExt for RequestBuilder {
        fn protobuf<T: Message + Default>(self, value: T) -> Self {
            let mut buf = Vec::new();
            value
                .encode(&mut buf)
                .expect("protobuf encoding to Vec is infallible");
            self.header(header::CONTENT_TYPE, "application/x-protobuf")
                .body(buf)
        }
    }

    #[async_trait::async_trait]
    pub(crate) trait ProtobufResponseExt {
        /// Get the response body decoded from Protobuf
        async fn protobuf<T>(self) -> Result<T, ServiceError>
        where
            T: prost::Message + Default;
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
}
