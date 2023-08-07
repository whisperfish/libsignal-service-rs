use std::str::FromStr;

use libsignal_service::configuration::{ServiceCredentials, SignalServers};
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::prelude::ProfileKey;
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::{
    AccountAttributes, DeviceCapabilities, PushService, RegistrationMethod,
    VerificationTransport,
};
use libsignal_service::USER_AGENT;

use libsignal_service_hyper::prelude::HyperPushService;

use rand::RngCore;

#[tokio::main]
async fn main() {
    let client = "libsignal-service-hyper-example";
    let phonenumber = let_user_enter_phone_number();
    let password = let_user_enter_password();
    let use_voice = does_user_want_voice_confirmation();
    let captcha = let_user_solve_captcha();
    let push_token = None;
    // Mobile country code and mobile network code can in theory be extracted from the phone
    // number, but it's not necessary for the API to function correctly.
    // XXX: We could internalize this if statement to create_verification_session
    let (mcc, mnc) = if let Some(carrier) = phonenumber.carrier() {
        (Some(&carrier[0..3]), Some(&carrier[3..]))
    } else {
        (None, None)
    };

    let mut push_service =
        create_push_service(phonenumber.clone(), password.clone());
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
                Some(&captcha),
                None,
            )
            .await
            .expect("submit captcha");
    }

    if session.push_challenge_required() {
        eprintln!("Push challenge required, but not implemented.");
        return;
    }

    if !session.allowed_to_request_code {
        eprintln!(
            "Not allowed to request verification code, reason unknown: {session:?}",
        );
        return;
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
        eprintln!("Session is not verified");
        return;
    }

    let registration_id = generate_registration_id(&mut rand::thread_rng());
    let pni_registration_id = generate_registration_id(&mut rand::thread_rng());
    let signaling_key = generate_signaling_key();
    let mut profile_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut profile_key);
    let profile_key = ProfileKey::create(profile_key);
    let skip_device_transfer = false;
    let _registration_data = push_service
        .submit_registration_request(
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
            skip_device_transfer,
        )
        .await;

    // You would want to store the registration data

    println!("Registration completed!");
}

fn generate_signaling_key() -> [u8; 52] {
    // Signaling key that decrypts the incoming Signal messages
    let mut rng = rand::thread_rng();
    let mut signaling_key = [0u8; 52];
    rng.fill_bytes(&mut signaling_key);
    signaling_key
}

fn create_push_service(
    phonenumber: PhoneNumber,
    password: String,
) -> HyperPushService {
    HyperPushService::new(
        SignalServers::Staging, // You might want to switch to Production servers
        Some(ServiceCredentials {
            uuid: None,
            phonenumber,
            password: Some(password),
            signaling_key: None,
            device_id: None,
        }),
        USER_AGENT.into(),
    )
}

// ------------------------------------
// Here come the user interaction mocks

fn let_user_solve_captcha() -> String {
    // Here you want to let the user solve a captcha on https://signalcaptchas.org/registration/generate.html
    "EnterCaptchaHere".to_string()
}

fn let_user_enter_confirmation_code() -> &'static str {
    "12345"
}

fn does_user_want_voice_confirmation() -> bool {
    false
}

fn let_user_enter_phone_number() -> PhoneNumber {
    PhoneNumber::from_str("+49301234567").expect("Not a valid phone number")
}

fn let_user_enter_password() -> String {
    "EnterPasswordHere".to_string()
}
