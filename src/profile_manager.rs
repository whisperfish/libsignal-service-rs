use libsignal_protocol::Aci;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use zkgroup::profiles::{
    ExpiringProfileKeyCredential, ProfileKey, ProfileKeyCredentialRequest,
};

use crate::profile_cipher::ProfileCipher;
use crate::profile_name::ProfileName;
use crate::push_service::{AvatarWrite, ServiceError};
use crate::unidentified_access::UnidentifiedAccess;
use crate::websocket::{self, SignalWebSocket};

pub struct ProfileManager {
    websocket: SignalWebSocket<websocket::Identified>,
    unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    profile_key: ProfileKey,

    server_params: zkgroup::ServerPublicParams,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub name: Option<ProfileName<String>>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
    pub avatar: Option<String>,
    pub unrestricted_unidentified_access: bool,
}

impl ProfileManager {
    pub fn new(
        websocket: SignalWebSocket<websocket::Identified>,
        unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
        profile_key: ProfileKey,
        server_params: zkgroup::ServerPublicParams,
    ) -> Self {
        Self {
            websocket,
            unidentified_websocket,
            profile_key,

            server_params,
        }
    }

    /// Upload a profile
    ///
    /// Panics if no `profile_key` was set.
    ///
    /// Convenience method for
    /// ```ignore
    /// manager.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _>(uuid, name, about, about_emoji, _)
    /// ```
    /// in which the `retain_avatar` parameter sets whether to remove (`false`) or retain (`true`) the
    /// currently set avatar.
    pub async fn upload_versioned_profile_without_avatar<
        R: Rng + CryptoRng,
        S: AsRef<str>,
    >(
        &mut self,
        aci: libsignal_protocol::Aci,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
        retain_avatar: bool,
        csprng: &mut R,
    ) -> Result<(), ServiceError> {
        self.upload_versioned_profile::<std::io::Cursor<Vec<u8>>, _, _>(
            aci,
            name,
            about,
            about_emoji,
            if retain_avatar {
                AvatarWrite::RetainAvatar
            } else {
                AvatarWrite::NoAvatar
            },
            csprng,
        )
        .await?;
        Ok(())
    }

    /// Retrieve a SignalServiceProfile.
    #[tracing::instrument(
        skip(self, sealed_sender_access),
        fields(
            sealed_sender_access=sealed_sender_access.is_some(),
            credential_request=credential_request.is_some(),
        ),
    )]
    pub async fn retrieve_service_profile(
        &mut self,
        address: Aci,
        profile_key: Option<ProfileKey>,
        sealed_sender_access: Option<UnidentifiedAccess>,
        credential_request: Option<ProfileKeyCredentialRequest>,
    ) -> Result<websocket::profile::SignalServiceProfile, ServiceError> {
        // Attempt unauthenticated profile fetching if sealed sender access is provided
        if let Some(access) = sealed_sender_access {
            match self
                .unidentified_websocket
                .retrieve_versioned_profile_and_credential(
                    address,
                    profile_key,
                    credential_request.as_ref(),
                    access,
                )
                .await
            {
                Ok(profile) => {
                    tracing::debug!(has_credential=%profile.credential.is_some(), "profile fetched unauthenticated");
                    return Ok(profile);
                },
                Err(ServiceError::Unauthorized) => {
                    tracing::debug!("unauthenticated profile fetching failed with 401, falling back to authenticated");
                },
                Err(e) => return Err(e),
            }
        }

        // Fall back to authenticated versioned profile fetching
        let encrypted_profile = self
            .websocket
            .retrieve_versioned_profile_and_credential(
                address,
                profile_key,
                credential_request.as_ref(),
            )
            .await?;
        Ok(encrypted_profile)
    }

    /// Retrieves and decrypts a profile.
    #[tracing::instrument(
        skip(self, sealed_sender_access),
        fields(
            sealed_sender_access=sealed_sender_access.is_some(),
        ),
    )]
    pub async fn retrieve_profile(
        &mut self,
        address: Aci,
        profile_key: ProfileKey,
        sealed_sender_access: Option<UnidentifiedAccess>,
    ) -> Result<Profile, ServiceError> {
        let service_profile = self
            .retrieve_service_profile(
                address,
                Some(profile_key),
                sealed_sender_access,
                None,
            )
            .await?;

        let profile_cipher = ProfileCipher::new(profile_key);
        Ok(profile_cipher.decrypt(service_profile)?)
    }

    /// Retrieves and decrypts a profile.
    #[tracing::instrument(
        skip(self, sealed_sender_access),
        fields(
            sealed_sender_access=sealed_sender_access.is_some(),
        ),
    )]
    pub async fn retrieve_profile_and_credential(
        &mut self,
        address: Aci,
        profile_key: ProfileKey,
        sealed_sender_access: Option<UnidentifiedAccess>,
    ) -> Result<(Profile, ExpiringProfileKeyCredential), ServiceError> {
        let request_context = self
            .server_params
            .create_profile_key_credential_request_context(
                rand::random(),
                address,
                profile_key,
            );

        let service_profile = self
            .retrieve_service_profile(
                address,
                Some(profile_key),
                sealed_sender_access,
                Some(request_context.get_request()),
            )
            .await?;

        let credential_response: zkgroup::profiles::ExpiringProfileKeyCredentialResponse =
            zkgroup::deserialize(
                service_profile.credential.as_deref().ok_or_else(|| {
                    ServiceError::InvalidFrame {
                        reason: "credential not present in response",
                    }
                })?,
            )?;

        let credential =
            self.server_params.receive_expiring_profile_key_credential(
                &request_context,
                &credential_response,
                std::time::SystemTime::now().into(),
            )?;

        let profile_cipher = ProfileCipher::new(profile_key);
        let profile = profile_cipher.decrypt(service_profile)?;

        Ok((profile, credential))
    }

    /// Upload a profile
    ///
    /// Panics if no `profile_key` was set.
    ///
    /// Returns the avatar url path.
    pub async fn upload_versioned_profile<
        's,
        C: std::io::Read + Send + 's,
        R: Rng + CryptoRng,
        S: AsRef<str>,
    >(
        &mut self,
        aci: libsignal_protocol::Aci,
        name: ProfileName<S>,
        about: Option<String>,
        about_emoji: Option<String>,
        avatar: AvatarWrite<&'s mut C>,
        csprng: &mut R,
    ) -> Result<Option<String>, ServiceError> {
        let profile_key = self.profile_key;
        let profile_cipher = ProfileCipher::new(profile_key);
        let name = profile_cipher.encrypt_name(name.as_ref(), csprng)?;
        let about = about.unwrap_or_default();
        let about = profile_cipher.encrypt_about(about, csprng)?;
        let about_emoji = about_emoji.unwrap_or_default();
        let about_emoji = profile_cipher.encrypt_emoji(about_emoji, csprng)?;

        // If avatar -> upload
        if matches!(avatar, AvatarWrite::NewAvatar(_)) {
            // FIXME ProfileCipherOutputStream.java
            // It's just AES GCM, but a bit of work to decently implement it with a stream.
            unimplemented!("Setting avatar requires ProfileCipherStream")
        }

        let profile_key = profile_cipher.into_inner();
        let commitment = profile_key.get_commitment(aci);
        let profile_key_version = profile_key.get_profile_key_version(aci);

        self.websocket
            .write_profile::<C, S>(
                &profile_key_version,
                &name,
                &about,
                &about_emoji,
                &commitment,
                avatar,
            )
            .await
    }
}
