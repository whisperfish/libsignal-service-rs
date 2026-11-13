use aes::cipher::block_padding;
use libsignal_core::{curve::CurveError, ServiceId};
use libsignal_protocol::{
    FingerprintError, ProtocolAddress, ServiceIdKind, SignalProtocolError,
};
use reqwest::StatusCode;
use serde::Deserialize;
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::{
    account_manager::DeviceInfoField,
    cipher::{InvalidEnvelope, SealedSenderDecryptionError},
    groups_v2::GroupDecodingError,
    push_service::cdn::CdnError,
    utils::deserialize_service_id,
    websocket::{
        registration::{
            RegistrationLockFailure, RegistrationSessionMetadataResponse,
        },
        InvalidFrame, UsernameLinkError, WebSocketError, WsClosingReason,
    },
};

use super::{MismatchedDevices, ProofRequired, StaleDevices};

#[derive(Debug, Deserialize)]
pub struct AccountMismatchedDevices {
    #[serde(deserialize_with = "deserialize_service_id")]
    pub uuid: ServiceId,
    pub devices: MismatchedDevices,
}

#[derive(Debug, Deserialize)]
pub struct AccountStaleDevices {
    #[serde(deserialize_with = "deserialize_service_id")]
    pub uuid: ServiceId,
    pub devices: StaleDevices,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationDeliveryFailure {
    #[serde(default)]
    pub reason: String,
    pub permanent_failure: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("request timed out, {attempts} times")]
    Timeout { attempts: u8 },

    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("wrong address type: {0}")]
    InvalidAddressType(ServiceIdKind),

    #[error("invalid phone number")]
    InvalidPhoneNumber,

    #[error("no identity key stored for {0}")]
    MissingIdentity(ProtocolAddress),

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

    #[error("Rate limit exceeded: retry after {}", retry_after.map(|a| a.to_string()).unwrap_or_else(|| "unspecified".into()))]
    RateLimitExceeded {
        retry_after: Option<chrono::Duration>,
    },
    #[error("Authorization failed")]
    Unauthorized,
    #[error("Registration lock is set: {0:?}")]
    Locked(RegistrationLockFailure),

    #[error("Unexpected response: HTTP {status}: {body}")]
    UnhandledResponseCode { status: StatusCode, body: String },

    #[error(transparent)]
    WebSocket(#[from] WebSocketError),
    #[error("websocket closing: {reason}")]
    WsClosing { reason: WsClosingReason },

    #[error("Invalid padding: {0}")]
    Padding(#[from] block_padding::Error),

    #[error("unknown padding version {0}")]
    PaddingVersion(u32),

    #[error("invalid websocket frame: {0}")]
    InvalidFrame(#[from] InvalidFrame),

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(#[from] InvalidEnvelope),

    #[error("CDN: {0}")]
    Cdn(#[from] CdnError),

    #[error("invalid username link: {0}")]
    InvalidUsernameLink(#[from] UsernameLinkError),

    #[error("the group credentials received don't cover day {day}")]
    MissingGroupCredential { day: u64 },

    #[error("MAC error")]
    MacError,

    #[error("Protocol error: {0}")]
    SignalProtocolError(#[from] SignalProtocolError),

    #[error("Sealed sender decryption error: {0}")]
    SealedSenderDecryptionError(#[from] SealedSenderDecryptionError),

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

    #[error("unsupported content")]
    UnsupportedContent,

    #[error("Not found.")]
    NotFoundError,

    #[error("couldn't decrypt the device's {field}")]
    InvalidDeviceInfo { field: DeviceInfoField },

    #[error("Unknown CDN version {0}")]
    UnknownCdnVersion(u32),

    #[error("Device limit reached: {current} out of {max} devices.")]
    DeviceLimitReached { current: u32, max: u32 },

    #[error("client version too old; upgrade required")]
    DeprecatedVersion,
    #[error("request rejected by the server")]
    ServerRejected,
    #[error("recipient is not registered")]
    UnregisteredRecipient,
    #[error("message too large")]
    MessageTooLarge,
    #[error("multi-recipient mismatched devices: {0:?}")]
    MultiRecipientMismatchedDevices(Vec<AccountMismatchedDevices>),
    #[error("multi-recipient stale devices: {0:?}")]
    MultiRecipientStaleDevices(Vec<AccountStaleDevices>),
    #[error("invalid device verification code")]
    InvalidDeviceVerificationCode,
    #[error("device capabilities are a downgrade")]
    DeviceCapabilityDowngrade,
    #[error("no such verification session")]
    NoSuchSession,
    #[error("invalid or malformed verification session id")]
    InvalidVerificationSessionId,
    #[error("verification token rejected: {0:?}")]
    TokenNotAccepted(RegistrationSessionMetadataResponse),
    #[error("verification session conflict: {0:?}")]
    RegistrationSessionConflict(RegistrationSessionMetadataResponse),
    #[error("verification session rate limited: {session:?}")]
    VerificationSessionRateLimited {
        session: RegistrationSessionMetadataResponse,
        retry_after: Option<chrono::Duration>,
    },
    #[error("verification transport not allowed: {0:?}")]
    InvalidTransportMode(RegistrationSessionMetadataResponse),
    #[error("verification code delivery failed: {0:?}")]
    VerificationDeliveryFailed(VerificationDeliveryFailure),
    #[error("device transfer required")]
    DeviceTransferAvailable,
    #[error("no username hash is set for this account")]
    UsernameHashNotSet,
    #[error("attachment too large")]
    AttachmentTooLarge,
    #[error("challenge token not accepted")]
    ChallengeNotAccepted,

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
    #[cfg(feature = "cdsi")]
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
