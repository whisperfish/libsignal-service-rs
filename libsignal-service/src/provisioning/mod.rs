mod cipher;
mod manager;
mod pipe;

pub use cipher::ProvisioningCipher;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt, StreamExt};
pub use manager::{
    ConfirmCodeMessage, ConfirmDeviceMessage, ProvisioningManager,
};

use pipe::{ProvisioningPipe, ProvisioningStep};

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};
use crate::{
    configuration::{ServiceConfiguration, SignalingKey},
    prelude::{PushService, ServiceError},
    USER_AGENT,
};

use libsignal_protocol::{
    generate_registration_id,
    keys::{PrivateKey, PublicKey},
    Context,
};
use url::Url;

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
    ProtocolError(#[from] libsignal_protocol::Error),
    #[error("ProvisioningCipher in encrypt-only mode")]
    EncryptOnlyProvisioningCipher,
}

use crate::push_service::DeviceId;

#[derive(Debug)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        phone_number: phonenumber::PhoneNumber,
        device_id: DeviceId,
        registration_id: u32,
        uuid: String,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: Vec<u8>,
    },
}

pub async fn provision_secondary_device<P: PushService>(
    ctx: &Context,
    cfg: impl Into<ServiceConfiguration>,
    signaling_key: SignalingKey,
    password: String,
    device_name: &str,
    mut tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), ProvisioningError> {
    assert_eq!(
        password.len(),
        24,
        "the password needs to be a 24 characters ASCII string"
    );

    // open a websocket without authentication, to receive a tsurl://
    let cfg = cfg.into();
    let mut push_service = P::new(cfg.clone(), None, USER_AGENT);
    let (ws, stream) =
        push_service.ws("/v1/websocket/provisioning/", None).await?;

    let registration_id = generate_registration_id(&ctx, 0)?;

    let provisioning_pipe = ProvisioningPipe::from_socket(ws, stream, &ctx)?;
    let provision_stream = provisioning_pipe.stream();
    pin_mut!(provision_stream);
    while let Some(step) = provision_stream.next().await {
        match step {
            Ok(ProvisioningStep::Url(url)) => {
                tx.send(SecondaryDeviceProvisioning::Url(url))
                    .await
                    .expect("failed to send provisioning Url in channel");
            }
            Ok(ProvisioningStep::Message(message)) => {
                let uuid =
                    message.uuid.ok_or(ProvisioningError::InvalidData {
                        reason: "missing client UUID".into(),
                    })?;

                let public_key = PublicKey::decode_point(
                    &ctx,
                    &message.identity_key_public.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing public key".into(),
                        },
                    )?,
                )?;

                let private_key = PrivateKey::decode_point(
                    &ctx,
                    &message.identity_key_private.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing public key".into(),
                        },
                    )?,
                )?;

                let profile_key = message.profile_key.ok_or(
                    ProvisioningError::InvalidData {
                        reason: "missing profile key".into(),
                    },
                )?;

                let phone_number =
                    message.number.ok_or(ProvisioningError::InvalidData {
                        reason: "missing phone number".into(),
                    })?;

                let phone_number = phonenumber::parse(None, phone_number)
                    .map_err(|e| ProvisioningError::InvalidData {
                        reason: format!("invalid phone number ({})", e),
                    })?;

                let mut provisioning_manager: ProvisioningManager<P> =
                    ProvisioningManager::new(
                        cfg.clone(),
                        phone_number.clone(),
                        password.to_string(),
                    );

                let device_id = provisioning_manager
                    .confirm_device(
                        message
                            .provisioning_code
                            .ok_or(ProvisioningError::InvalidData {
                                reason: "no provisioning confirmation code"
                                    .into(),
                            })?
                            .parse()
                            .unwrap(),
                        ConfirmDeviceMessage {
                            signaling_key: signaling_key.to_vec(),
                            supports_sms: false,
                            fetches_messages: true,
                            registration_id,
                            name: device_name.to_string(),
                        },
                    )
                    .await?;

                tx.send(SecondaryDeviceProvisioning::NewDeviceRegistration {
                    phone_number,
                    device_id,
                    registration_id,
                    uuid,
                    private_key,
                    public_key,
                    profile_key,
                })
                .await
                .expect("failed to send provisioning message in rx channel");
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
