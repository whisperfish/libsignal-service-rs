use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RecaptchaAttributes {
    pub r#type: String,
    pub token: String,
    pub captcha: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSessionMetadataResponse {
    pub id: String,
    #[serde(default)]
    pub next_sms: Option<i32>,
    #[serde(default)]
    pub next_call: Option<i32>,
    #[serde(default)]
    pub next_verification_attempt: Option<i32>,
    pub allowed_to_request_code: bool,
    #[serde(default)]
    pub requested_information: Vec<String>,
    pub verified: bool,
}

impl RegistrationSessionMetadataResponse {
    pub fn push_challenge_required(&self) -> bool {
        // .contains() requires &String ...
        self.requested_information
            .iter()
            .any(|x| x.as_str() == "pushChallenge")
    }

    pub fn captcha_required(&self) -> bool {
        // .contains() requires &String ...
        self.requested_information
            .iter()
            .any(|x| x.as_str() == "captcha")
    }
}
