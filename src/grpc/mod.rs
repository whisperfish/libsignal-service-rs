use std::time::Duration;

use base64::prelude::*;
use prost::Message;
use tonic::{
    codegen::GrpcMethod,
    metadata::{Ascii, MetadataValue},
    service::{interceptor::InterceptedService, Interceptor},
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
    Code, Request, Status,
};

use crate::{
    configuration::ServiceConfiguration,
    push_service::{HttpAuth, ServiceError},
};

pub use libsignal_net_grpc::proto;

pub type ChatChannel = InterceptedService<Channel, ChatInterceptor>;

/// Adds Basic auth on the authenticated channel and logs every call.
#[derive(Clone)]
pub struct ChatInterceptor {
    authorization: Option<MetadataValue<Ascii>>,
}

impl Interceptor for ChatInterceptor {
    fn call(
        &mut self,
        mut request: Request<()>,
    ) -> Result<Request<()>, Status> {
        if let Some(method) = request.extensions().get::<GrpcMethod>() {
            tracing::debug!(
                service = method.service(),
                method = method.method(),
                authenticated = self.authorization.is_some(),
                "gRPC call"
            );
        }
        if let Some(authorization) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", authorization.clone());
        }
        Ok(request)
    }
}

impl ChatInterceptor {
    fn anonymous() -> Self {
        Self {
            authorization: None,
        }
    }

    fn basic_auth(auth: &HttpAuth) -> Result<Self, ServiceError> {
        let token = BASE64_STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        let value = format!("Basic {token}").parse().map_err(|_| {
            ServiceError::InvalidFrame {
                reason: "credentials are not valid header characters",
            }
        })?;
        Ok(Self {
            authorization: Some(value),
        })
    }
}

/// Lazily-connected HTTP/2 channels to the chat server's gRPC endpoint.
///
/// Authenticated and anonymous calls use separate connections, as libsignal does.
#[derive(Clone)]
pub struct GrpcChannels {
    authenticated: Option<ChatChannel>,
    unauthenticated: ChatChannel,
}

impl GrpcChannels {
    pub fn new(
        cfg: &ServiceConfiguration,
        credentials: Option<&HttpAuth>,
        user_agent: &str,
    ) -> Result<Self, ServiceError> {
        let endpoint = endpoint(cfg, user_agent)?;
        let authenticated = credentials
            .map(|c| {
                Ok::<_, ServiceError>(InterceptedService::new(
                    endpoint.connect_lazy(),
                    ChatInterceptor::basic_auth(c)?,
                ))
            })
            .transpose()?;
        Ok(Self {
            authenticated,
            unauthenticated: InterceptedService::new(
                endpoint.connect_lazy(),
                ChatInterceptor::anonymous(),
            ),
        })
    }

    pub fn authenticated(&self) -> Result<ChatChannel, ServiceError> {
        self.authenticated.clone().ok_or(ServiceError::Unauthorized)
    }

    pub fn unauthenticated(&self) -> ChatChannel {
        self.unauthenticated.clone()
    }
}

fn endpoint(
    cfg: &ServiceConfiguration,
    user_agent: &str,
) -> Result<Endpoint, ServiceError> {
    let host = cfg.grpc_url.host_str().ok_or(ServiceError::InvalidFrame {
        reason: "gRPC URL has no host",
    })?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&cfg.certificate_authority))
        .domain_name(host);
    Ok(Endpoint::from_shared(cfg.grpc_url.to_string())?
        .tls_config(tls)?
        .user_agent(user_agent)?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_while_idle(true))
}

const RETRY_INFO_TYPE_URL: &str = "type.googleapis.com/google.rpc.RetryInfo";

impl From<Status> for ServiceError {
    fn from(status: Status) -> Self {
        tracing::debug!(code = ?status.code(), message = status.message(), "gRPC call failed");
        match status.code() {
            Code::Unauthenticated | Code::PermissionDenied => {
                ServiceError::Unauthorized
            },
            Code::NotFound => ServiceError::NotFoundError,
            Code::ResourceExhausted => ServiceError::RateLimitExceeded {
                retry_after: retry_after(&status),
            },
            _ => ServiceError::Grpc(Box::new(status)),
        }
    }
}

fn retry_after(status: &Status) -> Option<chrono::Duration> {
    let details = proto::google::rpc::Status::decode(status.details()).ok()?;
    let info = details
        .details
        .iter()
        .find(|any| any.type_url == RETRY_INFO_TYPE_URL)?;
    let delay = proto::google::rpc::RetryInfo::decode(info.value.as_slice())
        .ok()?
        .retry_delay?;
    Some(
        chrono::Duration::seconds(delay.seconds)
            + chrono::Duration::nanoseconds(delay.nanos.into()),
    )
}
