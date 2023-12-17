mod cipher;
mod pipe;

use std::convert::TryInto;
use std::{array::TryFromSliceError, borrow::Cow};

pub use cipher::ProvisioningCipher;

use derivative::Derivative;
use futures::StreamExt;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt};
use libsignal_protocol::{DeviceId, KeyPair, PrivateKey, PublicKey};
use prost::Message;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

use pipe::{ProvisioningPipe, ProvisioningStep};

use crate::prelude::ServiceError;
use crate::{
    account_manager::encrypt_device_name,
    pre_keys::{
        generate_last_resort_kyber_key, generate_signed_pre_key, PreKeysStore,
    },
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
    #[error("Invalid provisioning data: {reason}")]
    InvalidData { reason: Cow<'static, str> },
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
    #[error("invalid profile key bytes")]
    InvalidProfileKey(TryFromSliceError),
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
    pub aci_public_key: PublicKey,
    #[derivative(Debug = "ignore")]
    pub pni_private_key: PrivateKey,
    pub pni_public_key: PublicKey,
    #[derivative(Debug = "ignore")]
    pub profile_key: ProfileKey,
}

pub async fn link_device<
    R: rand::Rng + rand::CryptoRng,
    S: PreKeysStore,
    P: PushService,
>(
    aci_store: &mut S,
    pni_store: &mut S,
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

    if let ProvisioningStep::Url(url) = provision_stream.next().await.ok_or(
        ProvisioningError::InvalidData {
            reason: "no provisioning URL received".into(),
        },
    )?? {
        tx.send(SecondaryDeviceProvisioning::Url(url))
            .await
            .expect("failed to send provisioning Url in channel");
    } else {
        return Err(ProvisioningError::InvalidData {
            reason: "wrong provisioning step received".into(),
        });
    }

    if let ProvisioningStep::Message(message) =
        provision_stream.next().await.ok_or(
            ProvisioningError::InvalidData {
                reason: "no provisioning message received".into(),
            },
        )??
    {
        let aci_public_key =
            PublicKey::deserialize(&message.aci_identity_key_public.ok_or(
                ProvisioningError::InvalidData {
                    reason: "missing public key".into(),
                },
            )?)?;

        let aci_private_key =
            PrivateKey::deserialize(&message.aci_identity_key_private.ok_or(
                ProvisioningError::InvalidData {
                    reason: "missing public key".into(),
                },
            )?)?;

        let pni_public_key =
            PublicKey::deserialize(&message.pni_identity_key_public.ok_or(
                ProvisioningError::InvalidData {
                    reason: "missing public key".into(),
                },
            )?)?;

        let pni_private_key =
            PrivateKey::deserialize(&message.pni_identity_key_private.ok_or(
                ProvisioningError::InvalidData {
                    reason: "missing public key".into(),
                },
            )?)?;

        let profile_key =
            message.profile_key.ok_or(ProvisioningError::InvalidData {
                reason: "missing profile key".into(),
            })?;

        let phone_number =
            message.number.ok_or(ProvisioningError::InvalidData {
                reason: "missing phone number".into(),
            })?;

        let phone_number =
            phonenumber::parse(None, phone_number).map_err(|e| {
                ProvisioningError::InvalidData {
                    reason: format!("invalid phone number ({})", e).into(),
                }
            })?;

        let provisioning_code = message.provisioning_code.ok_or(
            ProvisioningError::InvalidData {
                reason: "no provisioning confirmation code".into(),
            },
        )?;

        let aci_key_pair = KeyPair::new(aci_public_key, aci_private_key);
        let pni_key_pair = KeyPair::new(pni_public_key, pni_private_key);

        let aci_pq_last_resort_pre_key =
            generate_last_resort_kyber_key(aci_store, &aci_key_pair).await?;
        let pni_pq_last_resort_pre_key =
            generate_last_resort_kyber_key(pni_store, &pni_key_pair).await?;

        let aci_signed_pre_key =
            generate_signed_pre_key(aci_store, csprng, &aci_key_pair).await?;
        let pni_signed_pre_key =
            generate_signed_pre_key(pni_store, csprng, &pni_key_pair).await?;

        let encrypted_device_name = base64::encode(
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
            aci_signed_pre_key: aci_signed_pre_key.try_into()?,
            pni_signed_pre_key: pni_signed_pre_key.try_into()?,
            aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key
                .try_into()?,
            pni_pq_last_resort_pre_key: pni_pq_last_resort_pre_key
                .try_into()?,
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
        return Err(ProvisioningError::InvalidData {
            reason: "wrong provisioning step received".into(),
        });
    }

    Ok(())
}
