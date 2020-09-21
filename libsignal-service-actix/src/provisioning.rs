use failure::Error;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt, StreamExt};
use serde::Serialize;
use url::Url;

use crate::push_service::AwcPushService;
use libsignal_protocol::{
    generate_registration_id, keys::PrivateKey, keys::PublicKey, Context,
};
use libsignal_service::{
    configuration::ServiceConfiguration, configuration::SignalServers,
    messagepipe::Credentials, prelude::PushService,
    provisioning::ProvisioningError, provisioning::ProvisioningPipe,
    provisioning::ProvisioningStep, push_service::ConfirmCodeMessage,
    push_service::DeviceId, push_service::PROVISIONING_WEBSOCKET_PATH,
    USER_AGENT,
};

#[derive(Debug, Serialize)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        device_id: DeviceId,
        uuid: String,
        #[serde(skip)]
        public_key: PublicKey,
        #[serde(skip)]
        private_key: PrivateKey,
    },
}

pub async fn provision_secondary_device(
    ctx: &Context,
    signaling_key: [u8; 52],
    password: [u8; 16],
    device_name: &str,
    mut tx: Sender<SecondaryDeviceProvisioning>,
) -> Result<(), Error> {
    let service_configuration: ServiceConfiguration =
        SignalServers::Production.into();

    let mut push_service =
        AwcPushService::new(service_configuration.clone(), None, USER_AGENT);

    let (ws, stream) =
        push_service.ws(PROVISIONING_WEBSOCKET_PATH, None).await?;

    let registration_id = generate_registration_id(&ctx, 0)?;

    let provisioning_pipe = ProvisioningPipe::from_socket(ws, stream, &ctx)?;
    let provision_stream = provisioning_pipe.stream();
    pin_mut!(provision_stream);
    while let Some(step) = provision_stream.next().await {
        match step {
            Ok(ProvisioningStep::Url(url)) => {
                tx.send(SecondaryDeviceProvisioning::Url(url)).await?;
            }
            Ok(ProvisioningStep::Message(message)) => {
                let credentials = Credentials {
                    e164: message.number.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing number".into(),
                        },
                    )?,
                    uuid: None,
                    password: Some(base64::encode(password)),
                    signaling_key,
                };

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

                let mut push_service = AwcPushService::new(
                    service_configuration.clone(),
                    Some(credentials),
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
                        &ConfirmCodeMessage {
                            signaling_key: signaling_key.to_vec(),
                            supports_sms: true,
                            fetches_messages: true,
                            registration_id,
                            name: device_name.to_string(),
                        },
                    )
                    .await?;

                tx.send(SecondaryDeviceProvisioning::NewDeviceRegistration {
                    device_id,
                    uuid,
                    public_key,
                    private_key,
                })
                .await?;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}
