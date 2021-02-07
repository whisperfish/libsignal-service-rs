use std::collections::HashMap;

use serde::Deserialize;
use zkgroup::auth::AuthCredentialResponse;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemporalCredential {
    credential: String,
    redemption_time: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    credentials: Vec<TemporalCredential>,
}

impl CredentialResponse {
    pub fn parse(self) -> HashMap<i64, AuthCredentialResponse> {
        self.credentials
            .into_iter()
            .map(|c| {
                let bytes = base64::decode(c.credential).unwrap();
                let data = bincode::deserialize(&bytes).unwrap();
                (c.redemption_time, data)
            })
            .collect()
    }
}
