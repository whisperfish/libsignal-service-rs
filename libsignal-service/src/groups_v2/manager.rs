use std::{collections::HashMap, convert::TryInto};

use crate::{
    configuration::Endpoint,
    groups_v2::model::{Group, GroupChanges},
    groups_v2::operations::{GroupDecodingError, GroupOperations},
    prelude::{PushService, ServiceError},
    proto::GroupContextV2,
    push_service::{HttpAuth, HttpAuthOverride, ServiceIds},
};

use bytes::Bytes;
use chrono::{Days, NaiveDate, NaiveTime, Utc};
use futures::AsyncReadExt;
use rand::RngCore;
use serde::Deserialize;
use zkgroup::{
    auth::AuthCredentialWithPniResponse,
    groups::{GroupMasterKey, GroupSecretParams},
    ServerPublicParams,
};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemporalCredential {
    credential: String,
    redemption_time: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialResponse {
    credentials: Vec<TemporalCredential>,
}

impl CredentialResponse {
    pub fn parse(
        self,
    ) -> Result<HashMap<u64, AuthCredentialWithPniResponse>, ServiceError> {
        self.credentials
            .into_iter()
            .map(|c| {
                let bytes = base64::decode(c.credential)?;
                let data = bincode::deserialize(&bytes)?;
                Ok((c.redemption_time, data))
            })
            .collect::<Result<_, ServiceError>>()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialsCacheError {
    #[error("failed to read values from cache: {0}")]
    ReadError(String),
    #[error("failed to write values from cache: {0}")]
    WriteError(String),
}

/// Global cache for groups v2 credentials, as demonstrated in the libsignal-service
/// java library of Signal-Android.
///
/// A basic in-memory implementation is provided with `InMemoryCredentialsCache`.
pub trait CredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError>;

    /// Get an entry of the cache, key usually represents the day number since EPOCH.
    fn get(
        &self,
        key: &u64,
    ) -> Result<Option<&AuthCredentialWithPniResponse>, CredentialsCacheError>;

    /// Overwrite the entire contents of the cache with new data.
    fn write(
        &mut self,
        map: HashMap<u64, AuthCredentialWithPniResponse>,
    ) -> Result<(), CredentialsCacheError>;
}

#[derive(Default)]
pub struct InMemoryCredentialsCache {
    map: HashMap<u64, AuthCredentialWithPniResponse>,
}

impl CredentialsCache for InMemoryCredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError> {
        self.map.clear();
        Ok(())
    }

    fn get(
        &self,
        key: &u64,
    ) -> Result<Option<&AuthCredentialWithPniResponse>, CredentialsCacheError>
    {
        Ok(self.map.get(key))
    }

    fn write(
        &mut self,
        map: HashMap<u64, AuthCredentialWithPniResponse>,
    ) -> Result<(), CredentialsCacheError> {
        self.map = map;
        Ok(())
    }
}

impl<T: CredentialsCache> CredentialsCache for &mut T {
    fn clear(&mut self) -> Result<(), CredentialsCacheError> {
        (**self).clear()
    }

    fn get(
        &self,
        key: &u64,
    ) -> Result<Option<&AuthCredentialWithPniResponse>, CredentialsCacheError>
    {
        (**self).get(key)
    }

    fn write(
        &mut self,
        map: HashMap<u64, AuthCredentialWithPniResponse>,
    ) -> Result<(), CredentialsCacheError> {
        (**self).write(map)
    }
}

pub struct GroupsManager<S: PushService, C: CredentialsCache> {
    service_ids: ServiceIds,
    push_service: S,
    credentials_cache: C,
    server_public_params: ServerPublicParams,
}

impl<S: PushService, C: CredentialsCache> GroupsManager<S, C> {
    pub fn new(
        service_ids: ServiceIds,
        push_service: S,
        credentials_cache: C,
        server_public_params: ServerPublicParams,
    ) -> Self {
        Self {
            service_ids,
            push_service,
            credentials_cache,
            server_public_params,
        }
    }

    pub async fn get_authorization_for_today(
        &mut self,
        group_secret_params: GroupSecretParams,
    ) -> Result<HttpAuth, ServiceError> {
        let (today, today_plus_7_days) = current_days_seconds();

        let auth_credential_response = if let Some(auth_credential_response) =
            self.credentials_cache.get(&today)?
        {
            auth_credential_response
        } else {
            let path =
            format!("/v1/certificate/auth/group?redemptionStartSeconds={}&redemptionEndSeconds={}", today, today_plus_7_days);

            let credentials_response: CredentialResponse = self
                .push_service
                .get_json(
                    Endpoint::Service,
                    &path,
                    &[],
                    HttpAuthOverride::NoOverride,
                )
                .await?;
            self.credentials_cache
                .write(credentials_response.parse()?)?;
            self.credentials_cache.get(&today)?.ok_or_else(|| {
                ServiceError::ResponseError {
                    reason:
                        "credentials received did not contain requested day"
                            .into(),
                }
            })?
        };

        self.get_authorization_string(
            group_secret_params,
            auth_credential_response,
            today,
        )
    }

    fn get_authorization_string(
        &self,
        group_secret_params: GroupSecretParams,
        credential_response: &AuthCredentialWithPniResponse,
        today: u64,
    ) -> Result<HttpAuth, ServiceError> {
        let auth_credential = self
            .server_public_params
            .receive_auth_credential_with_pni_as_aci(
                self.service_ids.aci(),
                self.service_ids.pni(),
                today,
                credential_response,
            )
            .map_err(|e| {
                tracing::error!(
                    "failed to receive auth credentials with PNI: {:?}",
                    e
                );
                ServiceError::GroupsV2Error
            })?;

        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        let auth_credential_presentation = self
            .server_public_params
            .create_auth_credential_with_pni_presentation(
                random_bytes,
                group_secret_params,
                auth_credential,
            );

        // see simpleapi.rs GroupSecretParams_getPublicParams, everything is bincode encoded
        // across the boundary of Rust/Java
        let username = hex::encode(bincode::serialize(
            &group_secret_params.get_public_params(),
        )?);

        let password =
            hex::encode(bincode::serialize(&auth_credential_presentation)?);

        Ok(HttpAuth { username, password })
    }

    #[deprecated = "please use fetch_encrypted_group and decrypt_group separately, which hide more of the implementation details"]
    pub async fn get_group(
        &mut self,
        group_secret_params: GroupSecretParams,
        credentials: HttpAuth,
    ) -> Result<Group, ServiceError> {
        let encrypted_group = self.push_service.get_group(credentials).await?;
        let decrypted_group = GroupOperations::new(group_secret_params)
            .decrypt_group(encrypted_group)?;

        Ok(decrypted_group)
    }

    pub async fn fetch_encrypted_group(
        &mut self,
        master_key_bytes: &[u8],
    ) -> Result<crate::proto::Group, ServiceError> {
        let group_master_key = GroupMasterKey::new(
            master_key_bytes
                .try_into()
                .map_err(|_| ServiceError::GroupsV2Error)?,
        );
        let group_secret_params =
            GroupSecretParams::derive_from_master_key(group_master_key);
        let authorization = self
            .get_authorization_for_today(group_secret_params)
            .await?;
        self.push_service.get_group(authorization).await
    }

    pub async fn retrieve_avatar(
        &mut self,
        path: &str,
        group_secret_params: GroupSecretParams,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        let mut encrypted_avatar = self
            .push_service
            .retrieve_groups_v2_profile_avatar(path)
            .await?;
        let mut result = Vec::with_capacity(10 * 1024 * 1024);
        encrypted_avatar
            .read_to_end(&mut result)
            .await
            .map_err(|e| ServiceError::ResponseError {
                reason: format!("reading avatar data: {}", e),
            })?;
        Ok(GroupOperations::new(group_secret_params).decrypt_avatar(&result))
    }

    pub fn decrypt_group_context(
        &self,
        group_context: GroupContextV2,
    ) -> Result<Option<GroupChanges>, GroupDecodingError> {
        match (group_context.master_key, group_context.group_change) {
            (Some(master_key), Some(group_change)) => {
                let master_key_bytes: [u8; 32] = master_key
                    .try_into()
                    .map_err(|_| GroupDecodingError::WrongBlob)?;
                let group_master_key = GroupMasterKey::new(master_key_bytes);
                let group_secret_params =
                    GroupSecretParams::derive_from_master_key(group_master_key);
                let encrypted_group_change =
                    prost::Message::decode(Bytes::from(group_change))?;
                let group_change = GroupOperations::new(group_secret_params)
                    .decrypt_group_change(encrypted_group_change)?;
                Ok(Some(group_change))
            },
            _ => Ok(None),
        }
    }
}

pub fn decrypt_group(
    master_key_bytes: &[u8],
    encrypted_group: crate::proto::Group,
) -> Result<Group, ServiceError> {
    let group_master_key = GroupMasterKey::new(
        master_key_bytes
            .try_into()
            .expect("wrong master key bytes length"),
    );
    let group_secret_params =
        GroupSecretParams::derive_from_master_key(group_master_key);

    Ok(GroupOperations::new(group_secret_params)
        .decrypt_group(encrypted_group)?)
}

fn current_days_seconds() -> (u64, u64) {
    let days_seconds = |date: NaiveDate| {
        date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
            .timestamp() as u64
    };

    let today = Utc::now().naive_utc().date();
    let today_plus_7_days = today + Days::new(7);

    (days_seconds(today), days_seconds(today_plus_7_days))
}
