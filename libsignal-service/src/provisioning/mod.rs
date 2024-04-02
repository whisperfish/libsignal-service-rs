mod cipher;
mod pipe;

use std::array::TryFromSliceError;
use std::convert::TryInto;

pub use cipher::ProvisioningCipher;

use base64::Engine;
use derivative::Derivative;
use futures::StreamExt;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt};
use libsignal_protocol::{
    DeviceId, IdentityKey, IdentityKeyPair, PrivateKey, PublicKey,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

use pipe::{ProvisioningPipe, ProvisioningStep};

use crate::prelude::ServiceError;
use crate::push_service::DeviceActivationRequest;
use crate::utils::BASE64_RELAXED;
use crate::{
    account_manager::encrypt_device_name,
    pre_keys::PreKeysStore,
    push_service::{
        HttpAuth, LinkAccountAttributes, LinkCapabilities, LinkRequest,
        LinkResponse, PushService, ServiceIds,
    },
    utils::serde_base64,
};

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

#[derive(thiserror::Error, Debug)]
pub enum ProvisioningError {
    #[error("no provisioning URL received")]
    MissingUrl,
    #[error("bad version number (unsupported)")]
    BadVersionNumber,
    #[error("missing public key")]
    MissingPublicKey,
    #[error("missing private key")]
    MissingPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey(InvalidKeyError),
    #[error("invalid privat key")]
    InvalidPrivateKey(InvalidKeyError),
    #[error("missing UUID")]
    MissingUuid,
    #[error("no provisioning message received")]
    MissingMessage,
    #[error("missing profile key")]
    MissingProfileKey,
    #[error("missing phone number")]
    MissingPhoneNumber,
    #[error("invalid phone number: {0}")]
    InvalidPhoneNumber(phonenumber::ParseError),
    #[error("missing provisioning code")]
    MissingProvisioningCode,
    #[error("mismatched MAC")]
    MismatchedMac,
    #[error("AES CBC padding error: {0}")]
    AesPaddingError(aes::cipher::block_padding::UnpadError),

    #[error("invalid provisioning step received")]
    InvalidStep,

    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Websocket error: {reason}")]
    WsError { reason: String },
    #[error("Websocket closing: {reason}")]
    WsClosing { reason: String },
    #[error("Service error: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::SignalProtocolError),
    #[error("ProvisioningCipher in encrypt-only mode")]
    EncryptOnlyProvisioningCipher,
    #[error("invalid profile key bytes")]
    InvalidProfileKey(TryFromSliceError),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidKeyError {
    #[error("base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protocol error: {0}")]
    Protocol(#[from] libsignal_protocol::SignalProtocolError),
}

pub fn generate_registration_id<R: rand::Rng + rand::CryptoRng>(
    csprng: &mut R,
) -> u32 {
    csprng.gen_range(1..16380)
}

/// Message received when linking a new secondary device.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmDeviceMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub fetches_messages: bool,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    #[serde(with = "serde_base64", skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeResponse {
    pub uuid: Uuid,
    pub storage_capable: bool,
}

#[derive(Debug)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration(NewDeviceRegistration),
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct NewDeviceRegistration {
    pub phone_number: phonenumber::PhoneNumber,
    pub device_id: DeviceId,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    pub service_ids: ServiceIds,
    #[derivative(Debug = "ignore")]
    pub aci_private_key: PrivateKey,
    pub aci_public_key: IdentityKey,
    #[derivative(Debug = "ignore")]
    pub pni_private_key: PrivateKey,
    pub pni_public_key: IdentityKey,
    #[derivative(Debug = "ignore")]
    pub profile_key: ProfileKey,
}

pub async fn link_device<
    R: rand::Rng + rand::CryptoRng,
    Aci: PreKeysStore,
    Pni: PreKeysStore,
    P: PushService + Clone,
>(
    aci_store: &mut Aci,
    pni_store: &mut Pni,
    csprng: &mut R,
    mut push_service: P,
    password: &str,
    device_name: &str,
    mut tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), ProvisioningError> {
    // open a websocket without authentication, to receive a tsurl://
    let ws = push_service
        .ws(
            "/v1/websocket/provisioning/",
            "/v1/keepalive/provisioning",
            &[],
            None,
        )
        .await?;

    let registration_id = csprng.gen_range(1..256);
    let pni_registration_id = csprng.gen_range(1..256);

    let provisioning_pipe = ProvisioningPipe::from_socket(ws)?;
    let provision_stream = provisioning_pipe.stream();
    pin_mut!(provision_stream);

    if let ProvisioningStep::Url(url) = provision_stream
        .next()
        .await
        .ok_or(ProvisioningError::MissingUrl)??
    {
        tx.send(SecondaryDeviceProvisioning::Url(url))
            .await
            .expect("failed to send provisioning Url in channel");
    } else {
        return Err(ProvisioningError::InvalidStep);
    }

    if let ProvisioningStep::Message(message) =
        provision_stream
            .next()
            .await
            .ok_or(ProvisioningError::MissingMessage)??
    {
        let aci_public_key = PublicKey::deserialize(
            &message
                .aci_identity_key_public
                .ok_or(ProvisioningError::MissingPublicKey)?,
        )
        .map_err(|e| ProvisioningError::InvalidPublicKey(e.into()))?;
        let aci_public_key = IdentityKey::new(aci_public_key);

        let aci_private_key = PrivateKey::deserialize(
            &message
                .aci_identity_key_private
                .ok_or(ProvisioningError::MissingPrivateKey)?,
        )
        .map_err(|e| ProvisioningError::InvalidPrivateKey(e.into()))?;

        let pni_public_key = PublicKey::deserialize(
            &message
                .pni_identity_key_public
                .ok_or(ProvisioningError::MissingPublicKey)?,
        )
        .map_err(|e| ProvisioningError::InvalidPublicKey(e.into()))?;
        let pni_public_key = IdentityKey::new(pni_public_key);

        let pni_private_key = PrivateKey::deserialize(
            &message
                .pni_identity_key_private
                .ok_or(ProvisioningError::MissingPrivateKey)?,
        )
        .map_err(|e| ProvisioningError::InvalidPrivateKey(e.into()))?;

        let profile_key = message
            .profile_key
            .ok_or(ProvisioningError::MissingProfileKey)?;

        let phone_number = message
            .number
            .ok_or(ProvisioningError::MissingPhoneNumber)?;

        let phone_number = phonenumber::parse(None, phone_number)
            .map_err(ProvisioningError::InvalidPhoneNumber)?;

        let provisioning_code = message
            .provisioning_code
            .ok_or(ProvisioningError::MissingProvisioningCode)?;

        let aci_key_pair =
            IdentityKeyPair::new(aci_public_key, aci_private_key);
        let pni_key_pair =
            IdentityKeyPair::new(pni_public_key, pni_private_key);

        let (
            _aci_pre_keys,
            aci_signed_pre_key,
            _aci_pq_pre_keys,
            aci_pq_last_resort_pre_key,
        ) = crate::pre_keys::replenish_pre_keys(
            aci_store,
            &aci_key_pair,
            csprng,
            true,
            0,
            0,
        )
        .await?;

        let aci_pq_last_resort_pre_key =
            aci_pq_last_resort_pre_key.expect("requested last resort key");
        assert!(_aci_pre_keys.is_empty());
        assert!(_aci_pq_pre_keys.is_empty());

        let (
            _pni_pre_keys,
            pni_signed_pre_key,
            _pni_pq_pre_keys,
            pni_pq_last_resort_pre_key,
        ) = crate::pre_keys::replenish_pre_keys(
            pni_store,
            &pni_key_pair,
            csprng,
            true,
            0,
            0,
        )
        .await?;

        let pni_pq_last_resort_pre_key =
            pni_pq_last_resort_pre_key.expect("requested last resort key");
        assert!(_pni_pre_keys.is_empty());
        assert!(_pni_pq_pre_keys.is_empty());

        let encrypted_device_name = BASE64_RELAXED.encode(
            encrypt_device_name(csprng, device_name, &aci_public_key)?
                .encode_to_vec(),
        );

        let profile_key = ProfileKey::create(
            profile_key
                .as_slice()
                .try_into()
                .map_err(ProvisioningError::InvalidProfileKey)?,
        );

        let request = LinkRequest {
            verification_code: provisioning_code,
            account_attributes: LinkAccountAttributes {
                registration_id,
                pni_registration_id,
                fetches_messages: true,
                capabilities: LinkCapabilities { pni: true },
                name: encrypted_device_name,
            },
            device_activation_request: DeviceActivationRequest {
                aci_signed_pre_key: aci_signed_pre_key.try_into()?,
                pni_signed_pre_key: pni_signed_pre_key.try_into()?,
                aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key
                    .try_into()?,
                pni_pq_last_resort_pre_key: pni_pq_last_resort_pre_key
                    .try_into()?,
            },
        };

        let LinkResponse {
            aci,
            pni,
            device_id,
        } = push_service
            .link_device(
                &request,
                HttpAuth {
                    username: phone_number.to_string(),
                    password: password.to_owned(),
                },
            )
            .await?;

        tx.send(SecondaryDeviceProvisioning::NewDeviceRegistration(
            NewDeviceRegistration {
                phone_number,
                service_ids: ServiceIds { aci, pni },
                device_id: device_id.into(),
                registration_id,
                pni_registration_id,
                aci_private_key,
                aci_public_key,
                pni_private_key,
                pni_public_key,
                profile_key,
            },
        ))
        .await
        .expect("failed to send provisioning message in rx channel");
    } else {
        return Err(ProvisioningError::InvalidStep);
    }

    Ok(())
}
