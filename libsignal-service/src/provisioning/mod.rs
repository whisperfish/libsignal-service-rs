mod cipher;
mod manager;
mod pipe;

pub use cipher::ProvisioningCipher;
pub use manager::{
    ConfirmCodeMessage, ConfirmCodeResponse, LinkingManager,
    ProvisioningManager, SecondaryDeviceProvisioning, VerificationCodeResponse,
    VerifyAccountResponse,
};

use crate::prelude::ServiceError;

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

#[derive(thiserror::Error, Debug)]
pub enum ProvisioningError {
    #[error("Invalid provisioning data: {reason}")]
    InvalidData { reason: String },
    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Websocket error: {reason}")]
    WsError { reason: String },
    #[error("Websocket closing: {reason}")]
    WsClosing { reason: String },
    #[error("Service error: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::error::SignalProtocolError),
    #[error("ProvisioningCipher in encrypt-only mode")]
    EncryptOnlyProvisioningCipher,
}

pub fn generate_registration_id<R: rand::Rng + rand::CryptoRng>(
    csprng: &mut R,
) -> u32 {
    csprng.gen_range(1, 16380)
}
