use failure::Error;
use futures::{StreamExt, *};
use serde::Serialize;
use std::{path::PathBuf, str::FromStr};
use structopt::StructOpt;

use libsignal_protocol::{
    crypto::DefaultCrypto,
    keys::{PrivateKey, PublicKey},
    Context, Serializable,
};
use libsignal_service::{
    configuration::*,
    prelude::PushService,
    provisioning::{ProvisioningError, ProvisioningPipe, ProvisioningStep},
    push_service::{ConfirmCodeMessage, DeviceId, PROVISIONING_WEBSOCKET_PATH},
    USER_AGENT,
};
use libsignal_service_actix::prelude::AwcPushService;
#[derive(Debug, Clone)]
struct Base64Data(Vec<u8>);

impl FromStr for Base64Data {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Base64Data(base64::decode(s)?))
    }
}

impl Base64Data {
    fn to_string(&self) -> String {
        base64::encode(&self.0)
    }
}

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(
        short = "p",
        long = "password",
        help = "The password to use, 16 bytes base64 encoded"
    )]
    pub password: Base64Data,
    #[structopt(
        long = "signaling-key",
        help = "The key used to encrypt and authenticate messages in transit, 52 bytes base64 encoded"
    )]
    pub signaling_key: Base64Data,
    #[structopt(
        long = "device-name",
        help = "Name of the device to register in the primary client"
    )]
    pub device_name: String,
    #[structopt(
        long = "output",
        help = "Output directory to save the provisioned key pair and device-id"
    )]
    pub output: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NewDeviceRegistration {
    device_id: DeviceId,
    uuid: String,
    #[serde(skip)]
    public_key: PublicKey,
    #[serde(skip)]
    private_key: PrivateKey,
}

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let args = Args::from_args();

    let registration = provision_secondary_device(&args).await?;

    std::fs::write(
        args.output.join("public.pem"),
        registration.public_key.serialize()?.as_slice(),
    )?;

    std::fs::write(
        args.output.join("private.pem"),
        registration.private_key.serialize()?.as_slice(),
    )?;

    std::fs::write(
        args.output.join("device.json"),
        serde_json::to_vec(&registration)?,
    )?;

    Ok(())
}

async fn provision_secondary_device(
    args: &Args,
) -> Result<NewDeviceRegistration, Error> {
    let ctx = Context::new(DefaultCrypto::default()).unwrap();

    let service_configuration = ServiceConfiguration::production();

    // TODO: we need a better way to get the WS without the pushservice here
    let mut push_service =
        AwcPushService::new(service_configuration.clone(), None, USER_AGENT);

    let (ws, stream) =
        push_service.ws(PROVISIONING_WEBSOCKET_PATH, None).await?;

    let registration_id =
        libsignal_protocol::generate_registration_id(&ctx, 0)?;
    let mut signaling_key = [0; 52];
    signaling_key.copy_from_slice(&args.signaling_key.0);

    let provisioning_pipe = ProvisioningPipe::from_socket(ws, stream, &ctx)?;
    let provision_stream = provisioning_pipe.stream();
    pin_mut!(provision_stream);
    while let Some(step) = provision_stream.next().await {
        match step {
            Ok(ProvisioningStep::Url(url)) => {
                log::info!(
                    "generating qrcode from provisioning link: {}",
                    &url
                );
                use image::Luma;
                let code = qrcode::QrCode::new(url.as_str())
                    .expect("failed to generate qrcode");
                let image = code.render::<Luma<u8>>().build();
                let path = std::env::temp_dir().join("device-link.png");
                image.save(&path).expect("failed to save qrcode");
                opener::open(path).expect("failed to open qrcode");
            }
            Ok(ProvisioningStep::Message(message)) => {
                let credentials = Credentials {
                    e164: message.number.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing number".into(),
                        },
                    )?,
                    uuid: None,
                    password: Some(args.password.to_string()),
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
                            name: args.device_name.clone(),
                        },
                    )
                    .await?;

                return Ok(NewDeviceRegistration {
                    device_id,
                    uuid,
                    public_key,
                    private_key,
                });
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(failure::err_msg("failed to link/provision new device"))
}
