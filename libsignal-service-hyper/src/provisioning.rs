use futures::{channel::mpsc::Sender, pin_mut, SinkExt, StreamExt};
use url::Url;

use crate::push_service::AwcPushService;
use libsignal_protocol::{
    generate_registration_id,
    keys::{PrivateKey, PublicKey},
    Context,
};
use libsignal_service::{
    configuration::ServiceConfiguration,
    messagepipe::Credentials,
    prelude::PushService,
    provisioning::{ProvisioningError, ProvisioningPipe, ProvisioningStep},
    push_service::{ConfirmDeviceMessage, DeviceId},
    USER_AGENT,
};

#[derive(Debug)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        phone_number: String,
        device_id: DeviceId,
        registration_id: u32,
        uuid: String,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: Vec<u8>,
    },
}

pub async fn provision_secondary_device(
    ctx: &Context,
    service_configuration: &ServiceConfiguration,
    signaling_key: &[u8; 52],
    password: &str,
    device_name: &str,
    mut tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), ProvisioningError> {
    assert_eq!(
        password.len(),
        24,
        "the password needs to be a 24 characters ASCII string"
    );

    let mut push_service =
        AwcPushService::new(service_configuration.clone(), None, USER_AGENT);

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

                // we need to authenticate with the phone number
                // to confirm the new device
                let mut push_service = AwcPushService::new(
                    service_configuration.clone(),
                    Some(Credentials {
                        e164: phone_number.clone(),
                        uuid: None,
                        password: Some(password.to_string()),
                        signaling_key: Some(*signaling_key),
                    }),
                    USER_AGENT,
                );

                let device_id = push_service
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
