use anyhow::Error;
use futures::{channel::mpsc::channel, future, StreamExt};
use image::Luma;
use libsignal_service::{
    configuration::SignalServers, provisioning::LinkingManager,
    provisioning::SecondaryDeviceProvisioning, USER_AGENT,
};
use libsignal_service_actix::prelude::AwcPushService;
use log::LevelFilter;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(long = "servers", short = "s", default_value = "staging")]
    servers: SignalServers,
}

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(LevelFilter::Info)
        .init();
    let args = Args::from_args();

    // generate a random 16 bytes password
    let mut csprng = rand::thread_rng();
    let password: String = csprng.sample_iter(&Alphanumeric).take(24).collect();

    // generate a 52 bytes signaling key
    let mut signaling_key = [0u8; 52];
    csprng.fill_bytes(&mut signaling_key);
    log::info!("generated signaling key: {}", base64::encode(signaling_key));

    let push_service =
        AwcPushService::new(args.servers, None, USER_AGENT.into());

    let mut provision_manager: LinkingManager<AwcPushService> =
        LinkingManager::new(push_service, password);

    let (tx, mut rx) = channel(1);

    let (fut1, fut2) = future::join(
        provision_manager.provision_secondary_device(
            &mut csprng,
            signaling_key,
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
                    },
                    SecondaryDeviceProvisioning::NewDeviceRegistration {
                        phone_number: _,
                        device_id: _,
                        registration_id: _,
                        service_ids,
                        profile_key: _,
                        aci_private_key: _,
                        aci_public_key: _,
                        pni_private_key: _,
                        pni_public_key: _,
                        pni_registration_id: _,
                    } => {
                        log::info!(
                            "successfully registered device {}",
                            &service_ids
                        );
                        // here you would store all of this data somehow to use it later!
                    },
                }
            }
            Result::Ok::<(), Error>(())
        },
    )
    .await;

    fut1?;
    fut2?;

    Ok(())
}
