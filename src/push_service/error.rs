use aes::cipher::block_padding::UnpadError;
use libsignal_core::curve::CurveError;
use libsignal_protocol::{
    FingerprintError, ServiceIdKind, SignalProtocolError,
};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::{
    groups_v2::GroupDecodingError,
    websocket::registration::RegistrationLockFailure,
};

use super::{MismatchedDevices, ProofRequired, StaleDevices};

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("Service request timed out: {reason}")]
    Timeout { reason: &'static str },

    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("wrong address type: {0}")]
    InvalidAddressType(ServiceIdKind),

    #[error("invalid phone number")]
    InvalidPhoneNumber,

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
    WsError(Box<reqwest_websocket::Error>),
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

    #[error("invalid device id: {0}")]
    InvalidDeviceId(#[from] libsignal_core::InvalidDeviceId),

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

    #[error(transparent)]
    ZkGroupVerificationFailure(#[from] ZkGroupVerificationFailure),

    // Group V2 modification errors
    /// Group revision conflict (HTTP 409 Conflict).
    ///
    /// Returned when a client attempts to modify a group with an outdated revision number.
    /// The client must:
    /// 1. Fetch the latest group state
    /// 2. Rebase their changes on top of the new revision
    /// 3. Retry the modification with the updated revision
    #[error("Group revision conflict: client must rebase changes")]
    GroupRevisionConflict,

    /// Group operation forbidden (HTTP 403 Forbidden).
    ///
    /// Returned when a user lacks permissions to perform the operation, such as:
    /// - Non-member trying to modify a group
    /// - Non-admin trying to perform admin-only operations
    /// - Requesting member trying to modify before being promoted
    #[error("Group operation forbidden: insufficient permissions")]
    GroupForbidden,

    /// Group not found (HTTP 404 Not Found).
    ///
    /// Returned when the specified group does not exist.
    #[error("Group not found")]
    GroupNotFound,

    /// Group has been deleted (HTTP 410 Gone).
    ///
    /// Returned when attempting to access a group that has been deleted.
    #[error("Group has been deleted")]
    GroupGone,

    #[error("unsupported content")]
    UnsupportedContent,

    #[error("Not found.")]
    NotFoundError,

    #[error("failed to decrypt field from device info: {0}")]
    DecryptDeviceInfoFieldError(&'static str),

    #[error("Unknown CDN version {0}")]
    UnknownCdnVersion(u32),

    #[error("Device limit reached: {current} out of {max} devices.")]
    DeviceLimitReached { current: u32, max: u32 },

    #[error("HTTP reqwest error: {0}")]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Curve(#[from] CurveError),

    // HpkeError does not implement StdError, so we need a manual display,
    // and manual From impl.
    #[error("Cryptographic error: {0}")]
    Hpke(signal_crypto::HpkeError),

    // FingerprintError does not implement StdError, so we need a manual display,
    // and manual From impl.
    #[error("Fingerprint error: {0}")]
    Fingerprint(FingerprintError),

    #[error("CDSI lookup error: {0}")]
    CdsiLookupError(#[from] libsignal_net::cdsi::LookupError),
}

impl From<signal_crypto::HpkeError> for ServiceError {
    fn from(value: signal_crypto::HpkeError) -> Self {
        ServiceError::Hpke(value)
    }
}

impl From<FingerprintError> for ServiceError {
    fn from(value: FingerprintError) -> Self {
        ServiceError::Fingerprint(value)
    }
}

impl From<reqwest_websocket::Error> for ServiceError {
    fn from(error: reqwest_websocket::Error) -> Self {
        Self::WsError(Box::new(error))
    }
}
