use failure::Error;
use futures::{channel::mpsc::channel, future, StreamExt};
use image::Luma;
use log::LevelFilter;
use qrcode::QrCode;
use rand::RngCore;
use std::path::PathBuf;
use structopt::StructOpt;

use libsignal_protocol::{crypto::DefaultCrypto, Context, Serializable};
use libsignal_service_actix::provisioning::{
    provision_secondary_device, SecondaryDeviceProvisioning,
};

#[derive(Debug, StructOpt)]
struct Args {
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

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(LevelFilter::Info)
        .init();
    let args = Args::from_args();

    if !args.output.exists() {
        return Err(failure::err_msg(format!(
            "directory {} does not exist.",
            args.output.display()
        )));
    }

    // generate a random 16 bytes password
    let mut rng = rand::rngs::OsRng::default();
    let mut password = [0u8; 16];
    rng.fill_bytes(&mut password);
    log::info!("generated password: {}", base64::encode(&password));

    // generate a 52 bytes signaling key
    let mut signaling_key = [0u8; 52];
    rng.fill_bytes(&mut signaling_key);
    log::info!(
        "generated signaling key: {}",
        base64::encode(&signaling_key.to_vec())
    );

    let signal_context = Context::new(DefaultCrypto::default()).unwrap();

    let (tx, mut rx) = channel(1);

    let output = args.output;

    let (fut1, fut2) = future::join(
        provision_secondary_device(
            &signal_context,
            signaling_key,
            password,
            &args.device_name,
            tx,
        ),
        async move {
            while let Some(provisioning_step) = rx.next().await {
                match provisioning_step {
                    SecondaryDeviceProvisioning::Url(url) => {
                        log::info!(
                            "generating qrcode from provisioning link: {}",
                            &url
                        );
                        let code = QrCode::new(url.as_str())
                            .expect("failed to generate qrcode");
                        let image = code.render::<Luma<u8>>().build();
                        let path = std::env::temp_dir().join("device-link.png");
                        image.save(&path)?;
                        opener::open(path)?;
                    }
                    SecondaryDeviceProvisioning::NewDeviceRegistration {
                        device_id: _,
                        uuid,
                        private_key,
                        public_key,
                    } => {
                        log::info!("successfully registered device {}", &uuid);
                        std::fs::write(
                            output.join("public.pem"),
                            public_key.serialize().unwrap().as_slice(),
                        )
                        .expect("failed to write public key");

                        std::fs::write(
                            output.join("private.pem"),
                            private_key.serialize().unwrap().as_slice(),
                        )
                        .expect("failed to write private key");

                        std::fs::write(output.join("device.uuid"), uuid)?;
                    }
                }
            }
            Result::Ok::<(), Error>(())
        },
    )
    .await;

    let _ = fut1?;
    let _ = fut2?;

    Ok(())
}
