use std::collections::HashMap;

use serde::Deserialize;
use zkgroup::auth::AuthCredentialResponse;

use crate::prelude::ServiceError;

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
    pub fn parse(
        self,
    ) -> Result<HashMap<i64, AuthCredentialResponse>, ServiceError> {
        Ok(self
            .credentials
            .into_iter()
            .map(|c| {
                let bytes = base64::decode(c.credential)?;
                let data = bincode::deserialize(&bytes)?;
                Ok((c.redemption_time, data))
            })
            .collect::<Result<_, ServiceError>>()?)
    }
}
