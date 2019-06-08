use crate::{TrustStore, USER_AGENT};
use failure::Error;

pub struct AccountManager;

impl AccountManager {
    pub fn builder() -> AccountManagerBuilder {
        AccountManagerBuilder::default()
    }

    pub fn request_sms_verification_code(&mut self) -> Result<(), Error> {
        unimplemented!()
    }
}

pub struct AccountManagerBuilder {
    username: Option<String>,
    password: Option<String>,
    user_agent: String,
    server: Option<String>,
    trust_store: Option<TrustStore>,
}

impl AccountManagerBuilder {
    pub fn credentials<U: Into<String>, P: Into<String>>(
        &mut self,
        username: U,
        password: P,
    ) -> &mut Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    pub fn server<S: Into<String>>(&mut self, server: S) -> &mut Self {
        self.server = Some(server.into());
        self
    }

    pub fn trust_store(&mut self, trust_store: TrustStore) -> &mut Self {
        self.trust_store = Some(trust_store);
        self
    }

    pub fn user_agent<U: Into<String>>(&mut self, user_agent: U) -> &mut Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn build(&mut self) -> AccountManager { AccountManager }
}

impl Default for AccountManagerBuilder {
    fn default() -> AccountManagerBuilder {
        AccountManagerBuilder {
            username: None,
            password: None,
            user_agent: String::from(USER_AGENT),
            server: None,
            trust_store: None,
        }
    }
}
