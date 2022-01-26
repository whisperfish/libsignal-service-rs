use std::str::FromStr;

use libsignal_service::configuration::{ServiceCredentials, SignalServers};
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::provisioning::{
    generate_registration_id, ConfirmCodeMessage, ConfirmCodeResponse,
    ProvisioningManager, VerificationCodeResponse,
};
use libsignal_service::push_service::{PushService, ServiceError};
use libsignal_service::USER_AGENT;

use libsignal_service_hyper::prelude::HyperPushService;

use rand::RngCore;

#[tokio::main]
async fn main() {
    let phonenumber = let_user_enter_phone_number();
    let password = let_user_enter_password();
    let use_voice = does_user_want_voice_confirmation();
    let captcha = let_user_solve_captcha();

    let mut push_service =
        create_push_service(phonenumber.clone(), password.clone());
    let mut manager =
        ProvisioningManager::new(&mut push_service, phonenumber, password);

    println!("Sending registration request...");

    let registration_result = register_user(&mut manager, captcha, use_voice)
        .await
        .expect("Sending registration request failed.");

    match registration_result {
        VerificationCodeResponse::Issued => {
            println!("Registration request was sent");
        },
        VerificationCodeResponse::CaptchaRequired => {
            println!("Captcha was wrong or not provided.");
            // Here you would go back to entering the Captcha
        },
    }

    let confirmation_code = let_user_enter_confirmation_code();

    println!("Sending confirmation code...");

    let _registration_data =
        confirm_registration(&mut manager, confirmation_code)
            .await
            .expect("Sending confirmation code failed.");
    // You would want to store the registration data

    println!("Registration completed!");
}

pub async fn register_user<'a, T: PushService>(
    manager: &mut ProvisioningManager<'a, T>,
    captcha: String,
    use_voice: bool,
) -> Result<VerificationCodeResponse, ServiceError> {
    if use_voice {
        manager
            .request_voice_verification_code(Some(&captcha), None)
            .await
    } else {
        manager
            .request_sms_verification_code(Some(&captcha), None)
            .await
    }
}

async fn confirm_registration<'a, T: PushService>(
    manager: &mut ProvisioningManager<'a, T>,
    confirmation_code: u32,
) -> Result<ConfirmCodeResponse, ServiceError> {
    let registration_id = generate_registration_id(&mut rand::thread_rng());
    let signaling_key = generate_signaling_key();

    manager
        .confirm_verification_code(
            confirmation_code,
            ConfirmCodeMessage::new_without_unidentified_access(
                signaling_key.to_vec(),
                registration_id,
            ),
        )
        .await
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

fn let_user_enter_confirmation_code() -> u32 {
    12345
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
