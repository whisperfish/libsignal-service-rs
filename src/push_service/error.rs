use aes::cipher::block_padding::UnpadError;
use libsignal_protocol::{ServiceIdKind, SignalProtocolError};
use zkgroup::ZkGroupDeserializationFailure;

use crate::groups_v2::GroupDecodingError;

use super::{
    MismatchedDevices, ProofRequired, RegistrationLockFailure, StaleDevices,
};

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("Service request timed out: {reason}")]
    Timeout { reason: &'static str },

    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("wrong address type: {0}")]
    InvalidAddressType(ServiceIdKind),

    #[error("Error sending request: {reason}")]
    SendError { reason: String },

    #[error("i/o error")]
    IO(#[from] std::io::Error),

    #[error("Error decoding JSON: {0}")]
    JsonDecodeError(#[from] serde_json::Error),
    #[error("Error decoding protobuf frame: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("error encoding or decoding bincode: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("error decoding base64 string: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Authorization failed")]
    Unauthorized,
    #[error("Registration lock is set: {0:?}")]
    Locked(RegistrationLockFailure),
    #[error("Unexpected response: HTTP {http_code}")]
    UnhandledResponseCode { http_code: u16 },

    #[error("Websocket error: {0}")]
    WsError(#[from] reqwest_websocket::Error),
    #[error("Websocket closing: {reason}")]
    WsClosing { reason: &'static str },

    #[error("Invalid padding: {0}")]
    Padding(#[from] UnpadError),

    #[error("unknown padding version {0}")]
    PaddingVersion(u32),

    #[error("Invalid frame: {reason}")]
    InvalidFrame { reason: &'static str },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] SignalProtocolError),

    #[error("Proof required: {0:?}")]
    ProofRequiredError(ProofRequired),

    #[error("{0:?}")]
    MismatchedDevicesException(MismatchedDevices),

    #[error("{0:?}")]
    StaleDevices(StaleDevices),

    #[error(transparent)]
    CredentialsCacheError(#[from] crate::groups_v2::CredentialsCacheError),

    #[error("groups v2 (zero-knowledge) error")]
    GroupsV2Error,

    #[error(transparent)]
    GroupsV2DecryptionError(#[from] GroupDecodingError),

    #[error(transparent)]
    ZkGroupDeserializationFailure(#[from] ZkGroupDeserializationFailure),

    #[error("unsupported content")]
    UnsupportedContent,

    #[error("Not found.")]
    NotFoundError,

    #[error("invalid device name")]
    InvalidDeviceName,

    #[error("Unknown CDN version {0}")]
    UnknownCdnVersion(u32),

    #[error("HTTP reqwest error: {0}")]
    Http(#[from] reqwest::Error),
}
