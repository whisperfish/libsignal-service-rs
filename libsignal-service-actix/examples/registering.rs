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

use failure::Error;
use libsignal_protocol::Context;
use libsignal_service::{configuration::*, AccountManager};
use libsignal_service_actix::push_service::AwcPushService;
use std::io;
use structopt::StructOpt;

#[actix_rt::main]
async fn main() -> Result<(), Error> {
    let args = Args::from_args();

    // Only used with MessageSender and MessageReceiver
    let password = args.get_password()?;

    let config: ServiceConfiguration = SignalServers::Staging.into();

    let mut signaling_key = [0u8; 52];
    base64::decode_config_slice(
        args.signaling_key,
        base64::STANDARD,
        &mut signaling_key,
    )
    .unwrap();
    let credentials = Credentials {
        uuid: None,
        e164: args.username.clone(),
        password: Some(password),
        signaling_key: Some(signaling_key),
    };

    let signal_context = Context::default();

    let push_service =
        AwcPushService::new(config, Some(credentials), &args.user_agent);

    let mut account_manager =
        AccountManager::new(signal_context, push_service, None);
    account_manager
        // You probably want to generate a reCAPTCHA though!
        .request_sms_verification_code(&args.username, None, None)
        .await?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct Args {
    #[structopt(
        short = "s",
        long = "server",
        help = "The server to connect to",
        default_value = "staging"
    )]
    pub servers: SignalServers,
    #[structopt(
        short = "u",
        long = "username",
        help = "Your username or other identifier",
        default_value = "+14151231234"
    )]
    pub username: String,
    #[structopt(
        short = "p",
        long = "password",
        help = "The password to use. Read from stdin if not provided"
    )]
    pub password: Option<String>,
    #[structopt(
        long = "user-agent",
        help = "The user agent to use when contacting servers",
        default_value = "libsignal_service::USER_AGENT"
    )]
    pub user_agent: String,
    #[structopt(
        long = "signaling-key",
        help = "The key used to encrypt and authenticate messages in transit, base64 encoded."
    )]
    pub signaling_key: String,
}

impl Args {
    pub fn get_password(&self) -> Result<String, Error> {
        if let Some(ref pw) = self.password {
            return Ok(pw.clone());
        }

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        Ok(line.trim().to_string())
    }
}
