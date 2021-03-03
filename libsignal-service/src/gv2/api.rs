use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    configuration::Endpoint,
    prelude::{PushService, ServiceError},
    proto::DecryptedGroup,
    push_service::HttpCredentials,
};

use rand::RngCore;
use uuid::Uuid;
use zkgroup::{
    auth::AuthCredentialResponse, groups::GroupSecretParams, ServerPublicParams,
};

use super::{models::CredentialResponse, operations::GroupOperations};

#[derive(Debug, thiserror::Error)]
pub enum CredentialsCacheError {
    #[error("failed to read values from cache: {0}")]
    ReadError(String),
    #[error("failed to write values from cache: {0}")]
    WriteError(String),
}

pub trait CredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError>;

    fn get(
        &self,
        key: &i64,
    ) -> Result<Option<&AuthCredentialResponse>, CredentialsCacheError>;

    fn write(
        &mut self,
        map: HashMap<i64, AuthCredentialResponse>,
    ) -> Result<(), CredentialsCacheError>;
}

#[derive(Default)]
pub struct InMemoryCredentialsCache {
    map: HashMap<i64, AuthCredentialResponse>,
}

impl CredentialsCache for InMemoryCredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError> {
        self.map.clear();
        Ok(())
    }

    fn get(
        &self,
        key: &i64,
    ) -> Result<Option<&AuthCredentialResponse>, CredentialsCacheError> {
        Ok(self.map.get(key))
    }

    fn write(
        &mut self,
        mut map: HashMap<i64, AuthCredentialResponse>,
    ) -> Result<(), CredentialsCacheError> {
        std::mem::swap(&mut self.map, &mut map);
        Ok(())
    }
}

pub struct GroupsV2Api<'a, S: PushService, C: CredentialsCache> {
    push_service: S,
    credentials_cache: &'a mut C,
    server_public_params: ServerPublicParams,
}

impl<'a, S: PushService, C: CredentialsCache> GroupsV2Api<'a, S, C> {
    pub fn new(
        push_service: S,
        credentials_cache: &'a mut C,
        server_public_params: ServerPublicParams,
    ) -> Self {
        Self {
            push_service,
            credentials_cache,
            server_public_params,
        }
    }

    pub async fn get_authorization_for_today(
        &mut self,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
    ) -> Result<HttpCredentials, ServiceError> {
        let today = Self::current_time_days();
        let auth_credential_response = if let Some(auth_credential_response) =
            self.credentials_cache.get(&today)?
        {
            auth_credential_response
        } else {
            let credentials_map = self.get_authorization(today).await?.parse();
            self.credentials_cache.write(credentials_map)?;
            self.credentials_cache.get(&today)?.ok_or_else(|| {
                ServiceError::ResponseError {
                    reason:
                        "credentials received did not contain requested day"
                            .into(),
                }
            })?
        };

        self.get_authorization_string(
            uuid,
            group_secret_params,
            auth_credential_response,
            today as u32,
        )
    }

    async fn get_authorization(
        &mut self,
        today: i64,
    ) -> Result<CredentialResponse, ServiceError> {
        let today_plus_7_days = today + 7;

        let path =
            format!("/v1/certificate/group/{}/{}", today, today_plus_7_days);

        self.push_service
            .get_json(Endpoint::Service, &path, None)
            .await
    }

    fn current_time_days() -> i64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let today = chrono::Duration::from_std(now).unwrap();
        today.num_days()
    }

    fn get_authorization_string(
        &self,
        uuid: Uuid,
        group_secret_params: GroupSecretParams,
        credential_response: &AuthCredentialResponse,
        today: u32,
    ) -> Result<HttpCredentials, ServiceError> {
        let auth_credential = self
            .server_public_params
            .receive_auth_credential(
                *uuid.as_bytes(),
                today,
                credential_response,
            )
            .map_err(|e| {
                log::error!("zero-knowledge group error: {:?}", e);
                ServiceError::GroupsV2Error
            })?;

        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        let auth_credential_presentation = self
            .server_public_params
            .create_auth_credential_presentation(
                random_bytes,
                group_secret_params,
                auth_credential,
            );

        // see simpleapi.rs GroupSecretParams_getPublicParams, everything is bincode encoded
        // across the boundary of Rust/Java
        let username = hex::encode(bincode::serialize(
            &group_secret_params.get_public_params(),
        )?);

        let password = Some(hex::encode(bincode::serialize(
            &auth_credential_presentation,
        )?));

        Ok(HttpCredentials { username, password })
    }

    pub async fn get_group(
        &mut self,
        group_secret_params: GroupSecretParams,
        credentials: HttpCredentials,
    ) -> Result<DecryptedGroup, ServiceError> {
        let encrypted_group = self.push_service.get_group(credentials).await?;
        let decrypted_group = GroupOperations::decrypt_group(
            group_secret_params,
            encrypted_group,
        )?;

        Ok(decrypted_group)
    }
}
