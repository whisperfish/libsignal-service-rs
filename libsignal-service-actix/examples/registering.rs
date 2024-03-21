//! At install time, clients need to register with the Signal server.
//!
//! ```java
//! private final String     URL         = "https://my.signal.server.com";
//! private final TrustStore TRUST_STORE = new MyTrustStoreImpl();
//! private final String     USERNAME    = "+14151231234";
//! private final String     PASSWORD    = generateRandomPassword();
//! private final String     USER_AGENT  = "[FILL_IN]";
//!
//! SignalServiceAccountManager accountManager = new SignalServiceAccountManager(URL, TRUST_STORE,
//!                                                                              USERNAME, PASSWORD, USER_AGENT);
//!
//! accountManager.requestSmsVerificationCode();
//! accountManager.verifyAccountWithCode(receivedSmsVerificationCode, generateRandomSignalingKey(),
//!                                      generateRandomInstallId(), false);
//! accountManager.setGcmId(Optional.of(GoogleCloudMessaging.getInstance(this).register(REGISTRATION_ID)));
//! accountManager.setPreKeys(identityKey.getPublicKey(), lastResortKey, signedPreKeyRecord, oneTimePreKeys);
//! ```

use anyhow::Error;
use libsignal_service::configuration::SignalServers;
use libsignal_service::prelude::{ProfileKey, ServiceCredentials};
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::{
    AccountAttributes, DeviceCapabilities, PushService, RegistrationMethod,
    VerificationTransport,
};
use libsignal_service::{AccountManager, USER_AGENT};
use libsignal_service_actix::prelude::AwcPushService;
use rand::RngCore;
use structopt::StructOpt;

#[path = "../../libsignal-service/examples/storage.rs"]
mod storage;

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    let client = "libsignal-service-hyper-example";
    let use_voice = false;

    let Args {
        servers,
        phonenumber,
        password,
        captcha,
    } = Args::from_args();

    let push_token = None;
    // Mobile country code and mobile network code can in theory be extracted from the phone
    // number, but it's not necessary for the API to function correctly.
    // XXX: We could internalize this if statement to create_verification_session
    let (mcc, mnc) = if let Some(carrier) = phonenumber.carrier() {
        (Some(&carrier[0..3]), Some(&carrier[3..]))
    } else {
        (None, None)
    };

    // Only used with MessageSender and MessageReceiver
    // let password = args.get_password()?;

    let mut push_service = AwcPushService::new(
        servers,
        Some(ServiceCredentials {
            aci: None,
            pni: None,
            phonenumber: phonenumber.clone(),
            password,
            signaling_key: None,
            device_id: None,
        }),
        USER_AGENT.into(),
    );

    let mut session = push_service
        .create_verification_session(
            &phonenumber.to_string(),
            push_token,
            mcc,
            mnc,
        )
        .await
        .expect("create a registration verification session");
    println!("Sending registration request...");

    if session.captcha_required() {
        session = push_service
            .patch_verification_session(
                &session.id,
                None,
                None,
                None,
                captcha.as_deref(),
                None,
            )
            .await
            .expect("submit captcha");
    }

    if session.push_challenge_required() {
        anyhow::bail!("Push challenge required, but not implemented.");
    }

    if !session.allowed_to_request_code {
        anyhow::bail!(
            "Not allowed to request verification code, reason unknown: {session:?}",
        );
    }

    session = push_service
        .request_verification_code(
            &session.id,
            client,
            if use_voice {
                VerificationTransport::Voice
            } else {
                VerificationTransport::Sms
            },
        )
        .await
        .expect("request verification code");

    let confirmation_code = let_user_enter_confirmation_code();

    println!("Submitting confirmation code...");

    session = push_service
        .submit_verification_code(&session.id, confirmation_code)
        .await
        .expect("Sending confirmation code failed.");

    if !session.verified {
        anyhow::bail!("Session is not verified");
    }

    let registration_id = generate_registration_id(&mut rand::thread_rng());
    let pni_registration_id = generate_registration_id(&mut rand::thread_rng());
    let signaling_key = generate_signaling_key();
    let mut profile_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut profile_key);
    let profile_key = ProfileKey::create(profile_key);
    let skip_device_transfer = false;

    // Create the prekeys storage
    let mut aci_store = storage::ExampleStore::new();
    let mut pni_store = storage::ExampleStore::new();

    let mut account_manager = AccountManager::new(push_service, None);
    let _registration_data = account_manager
        .register_account(
            &mut rand::thread_rng(),
            RegistrationMethod::SessionId(&session.id),
            AccountAttributes {
                signaling_key: Some(signaling_key.to_vec()),
                registration_id,
                pni_registration_id,
                voice: false,
                video: false,
                fetches_messages: true,
                pin: None,
                registration_lock: None,
                unidentified_access_key: Some(
                    profile_key.derive_access_key().to_vec(),
                ),
                unrestricted_unidentified_access: false, // TODO: make this configurable?
                discoverable_by_phone_number: true,
                name: Some("libsignal-service-hyper test".into()),
                capabilities: DeviceCapabilities::default(),
            },
            &mut aci_store,
            &mut pni_store,
            skip_device_transfer,
        )
        .await;

    // You would want to store the registration data

    println!("Registration completed!");

    Ok(())
}

fn let_user_enter_confirmation_code() -> &'static str {
    "12345"
}

fn generate_signaling_key() -> [u8; 52] {
    // Signaling key that decrypts the incoming Signal messages
    let mut rng = rand::thread_rng();
    let mut signaling_key = [0u8; 52];
    rng.fill_bytes(&mut signaling_key);
    signaling_key
}

#[derive(Debug, Clone, PartialEq, Eq, StructOpt)]
pub struct Args {
    #[structopt(
        short = "s",
        long = "servers",
        help = "The servers to connect to",
        default_value = "staging"
    )]
    pub servers: SignalServers,
    #[structopt(
        short = "u",
        long = "username",
        help = "Your username or other identifier",
        default_value = "+14151231234"
    )]
    pub phonenumber: phonenumber::PhoneNumber,
    #[structopt(
        short = "p",
        long = "password",
        help = "The password to use. Read from stdin if not provided"
    )]
    pub password: Option<String>,
    #[structopt(
        short = "c",
        long = "captcha",
        help = "Captcha for registration"
    )]
    pub captcha: Option<String>,
}
