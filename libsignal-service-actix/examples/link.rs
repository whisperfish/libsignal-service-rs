use failure::Error;
use futures::{channel::mpsc::channel, future, StreamExt};
use image::Luma;
use libsignal_service::configuration::SignalServers;
use log::LevelFilter;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use structopt::StructOpt;

use libsignal_protocol::{crypto::DefaultCrypto, Context};
use libsignal_service_actix::provisioning::{
    provision_secondary_device, SecondaryDeviceProvisioning,
};

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(long = "servers", short = "s", default_value = "staging")]
    servers: SignalServers,
    #[structopt(
        long = "device-name",
        help = "Name of the device to register in the primary client"
    )]
    pub device_name: String,
}

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(LevelFilter::Info)
        .init();
    let args = Args::from_args();

    // generate a random 16 bytes password
    let mut rng = rand::rngs::OsRng::default();
    let password: Vec<u8> = rng.sample_iter(&Alphanumeric).take(24).collect();
    let password = std::str::from_utf8(&password)?;

    // generate a 52 bytes signaling key
    let mut signaling_key = [0u8; 52];
    rng.fill_bytes(&mut signaling_key);
    log::info!(
        "generated signaling key: {}",
        base64::encode(&signaling_key.to_vec())
    );

    let signal_context = Context::new(DefaultCrypto::default()).unwrap();
    let service_configuration = args.servers.into();

    let (tx, mut rx) = channel(1);

    let (fut1, fut2) = future::join(
        provision_secondary_device(
            &signal_context,
            &service_configuration,
            &signaling_key,
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
                        phone_number: _,
                        device_id: _,
                        registration_id: _,
                        uuid,
                        private_key: _,
                        public_key: _,
                        profile_key: _,
                    } => {
                        log::info!("successfully registered device {}", &uuid);
                        // here you would store all of this data somehow to use it later!
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
