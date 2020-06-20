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
use libsignal_service::{
    configuration::*, push_service::PanicingPushService, AccountManager,
    TrustStore,
};
use std::io;
use structopt::StructOpt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::from_args();

    // Only used with MessageSender and MessageReceiver
    let _trust_store = args.load_trust_store()?;
    let password = args.get_password()?;

    let config = ServiceConfiguration::default();
    let credentials = Credentials {
        uuid: None,
        e164: args.username,
        password: Some(password),
    };

    let service = PanicingPushService::new(
        config,
        credentials,
        libsignal_service::USER_AGENT,
    );

    let mut account_manager = AccountManager::new(service);
    account_manager.request_sms_verification_code().await?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct Args {
    #[structopt(
        short = "s",
        long = "server",
        help = "The server to connect to",
        default_value = "https://my.signal.server.com"
    )]
    pub url: String,
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
        raw(default_value = "libsignal_service::USER_AGENT")
    )]
    pub user_agent: String,
}

impl Args {
    pub fn load_trust_store(&self) -> Result<TrustStore, Error> {
        Ok(TrustStore)
    }

    pub fn get_password(&self) -> Result<String, Error> {
        if let Some(ref pw) = self.password {
            return Ok(pw.clone());
        }

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;

        Ok(line.trim().to_string())
    }
}
