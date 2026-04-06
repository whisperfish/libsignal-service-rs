use base64::Engine;
use libsignal_protocol::Aci;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zkgroup::profiles::{
    ProfileKeyCommitment, ProfileKeyCredentialRequest, ProfileKeyVersion,
};

use crate::{
    content::ServiceError,
    push_service::AvatarWrite,
    unidentified_access::UnidentifiedAccess,
    utils::{serde_base64, serde_optional_base64, BASE64_RELAXED},
    websocket::{
        self, account::DeviceCapabilities, SignalWebSocket, WebSocketType,
    },
};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfile {
    #[serde(default, with = "serde_optional_base64")]
    pub identity_key: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub name: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about: Option<Vec<u8>>,
    #[serde(default, with = "serde_optional_base64")]
    pub about_emoji: Option<Vec<u8>>,

    // TODO: not sure whether this is via optional_base64
    // #[serde(default, with = "serde_optional_base64")]
    // pub payment_address: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub unidentified_access: Option<String>,

    #[serde(default)]
    pub unrestricted_unidentified_access: bool,

    pub capabilities: DeviceCapabilities,

    #[serde(default, with = "serde_optional_base64")]
    pub credential: Option<Vec<u8>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignalServiceProfileWrite<'s> {
    /// Hex-encoded
    version: &'s str,
    #[serde(with = "serde_base64")]
    name: &'s [u8],
    #[serde(with = "serde_base64")]
    about: &'s [u8],
    #[serde(with = "serde_base64")]
    about_emoji: &'s [u8],
    avatar: bool,
    same_avatar: bool,
    #[serde(with = "serde_base64")]
    commitment: &'s [u8],
}

impl<T: WebSocketType> SignalWebSocket<T> {
    fn retrieve_versioned_profile_and_credential_path(
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
        credential_request: Option<
            impl std::borrow::Borrow<ProfileKeyCredentialRequest>,
        >,
    ) -> Result<String, ServiceError> {
        let path = if let Some(key) = profile_key {
            let version = key.get_profile_key_version(address);
            if let Some(req) = credential_request {
                let req = zkgroup::serialize(req.borrow());
                format!(
                    "/v1/profile/{}/{}/{}?credentialType=expiringProfileKey",
                    address.service_id_string(),
                    version.as_ref(),
                    hex::encode(req),
                )
            } else {
                format!(
                    "/v1/profile/{}/{}",
                    address.service_id_string(),
                    version.as_ref()
                )
            }
        } else {
            format!("/v1/profile/{}", address.service_id_string())
        };
        Ok(path)
    }
}

impl SignalWebSocket<websocket::Identified> {
    /// Retrieve a profile by service ID using authenticated access.
    ///
    /// Prefer the unauthenticated call when possible. See
    /// [SignalWebSocket<websocket::Unidentified>::retrieve_profile_by_id] for documentation.
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        // Delegate to the more general method with no credential request
        self.retrieve_versioned_profile_and_credential(
            address,
            profile_key,
            None::<ProfileKeyCredentialRequest>,
        )
        .await
    }

    /// Retrieve a versioned profile with optional credential support using authenticated access.
    ///
    /// Prefer the unauthenticated call when possible. See
    /// [SignalWebSocket<websocket::Unidentified>::retrieve_versioned_profile_and_credential] for documentation.
    pub async fn retrieve_versioned_profile_and_credential(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
        credential_request: Option<
            impl std::borrow::Borrow<ProfileKeyCredentialRequest>,
        >,
    ) -> Result<SignalServiceProfile, ServiceError> {
        // TODO: set locale to en_US
        self.http_request(
            Method::GET,
            Self::retrieve_versioned_profile_and_credential_path(
                address,
                profile_key,
                credential_request,
            )?,
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }

    /// Writes a profile and returns the avatar URL, if one was provided.
    ///
    /// The name, about and emoji fields are encrypted with an [`ProfileCipher`][struct@crate::profile_cipher::ProfileCipher].
    /// See [`AccountManager`][struct@crate::AccountManager] for a convenience method.
    ///
    /// Java equivalent: `writeProfile`
    pub async fn write_profile<'s, C, S>(
        &mut self,
        version: &ProfileKeyVersion,
        name: &[u8],
        about: &[u8],
        emoji: &[u8],
        commitment: &ProfileKeyCommitment,
        avatar: AvatarWrite<&mut C>,
    ) -> Result<Option<String>, ServiceError>
    where
        C: std::io::Read + Send + 's,
        S: AsRef<str>,
    {
        // Bincode is transparent and will return a hex-encoded string.
        let version = bincode::serialize(version)?;
        let version = std::str::from_utf8(&version)
            .expect("profile_key_version is hex encoded string");
        let commitment = bincode::serialize(commitment)?;

        let command = SignalServiceProfileWrite {
            version,
            name,
            about,
            about_emoji: emoji,
            avatar: !matches!(avatar, AvatarWrite::NoAvatar),
            same_avatar: matches!(avatar, AvatarWrite::RetainAvatar),
            commitment: &commitment,
        };

        let response = self
            .http_request(Method::PUT, "/v1/profile")?
            .send_json(&command)
            .await?
            .service_error_for_status()
            .await?;

        #[derive(Debug, Deserialize)]
        #[allow(unused)]
        struct ProfileAvatarUploadAttributes {
            key: String,
            credential: String,
            acl: String,
            algorithm: String,
            date: String,
            policy: String,
            signature: String,
        }

        match avatar {
            AvatarWrite::NewAvatar(_avatar) => {
                // XXX this should  be a struct; cfr ProfileAvatarUploadAttributes
                let _upload_attributes: Result<
                    ProfileAvatarUploadAttributes,
                    _,
                > = response.json().await;
                tracing::trace!("received upload attributes");
                unreachable!("Uploading avatar unimplemented");
            },
            AvatarWrite::RetainAvatar | AvatarWrite::NoAvatar => {
                // OWS sends an empty string when there's no attachment
                if !response.body().is_empty() {
                    tracing::warn!(response_len=%response.body().len(), "expected empty response");
                }
                Ok(None)
            },
        }
    }
}

impl SignalWebSocket<websocket::Unidentified> {
    /// Retrieve a profile by service ID using sealed sender access.
    ///
    /// This method fetches a profile using the unauthenticated websocket with sealed sender access.
    /// If a profile key is provided, it will fetch the versioned profile.
    /// Otherwise, it falls back to the unversioned profile.
    ///
    /// This is a convenience method that calls `retrieve_versioned_profile_and_credential`
    /// with no credential request.
    ///
    /// # Arguments
    ///
    /// * `address` - The ACI of the user whose profile to retrieve
    /// * `profile_key` - Optional profile key for fetching versioned profiles
    /// * `access` - Sealed sender access credentials for unauthenticated access
    ///
    /// # Returns
    ///
    /// The retrieved profile or an error (401 indicates fallback to authenticated method)
    ///
    /// # See Also
    ///
    /// For the version with credential support, see `retrieve_versioned_profile_and_credential`
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
        access: UnidentifiedAccess,
    ) -> Result<SignalServiceProfile, ServiceError> {
        // Delegate to the more general method with no credential request
        self.retrieve_versioned_profile_and_credential(
            address,
            profile_key,
            None::<ProfileKeyCredentialRequest>,
            access,
        )
        .await
    }

    /// Retrieve a versioned profile with optional credential support using sealed sender access.
    ///
    /// This method fetches a profile using the unauthenticated websocket with sealed sender access.
    /// It supports fetching versioned profiles with or without expiring profile key credentials.
    ///
    /// This is the primary method for profile retrieval when sealed sender access is available.
    /// On 401 errors, callers should fall back to the authenticated version:
    /// `SignalWebSocket<websocket::Identified>::retrieve_versioned_profile_and_credential`
    ///
    /// # Arguments
    ///
    /// * `address` - The ACI of the user whose profile to retrieve
    /// * `profile_key` - Optional profile key for fetching versioned profiles
    /// * `credential_request` - Optional credential request for expiring profile keys
    /// * `access` - Sealed sender access credentials for unauthenticated access
    ///
    /// # Returns
    ///
    /// The retrieved profile or an error (401 indicates fallback to authenticated method)
    pub async fn retrieve_versioned_profile_and_credential(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
        credential_request: Option<
            impl std::borrow::Borrow<ProfileKeyCredentialRequest>,
        >,
        access: UnidentifiedAccess,
    ) -> Result<SignalServiceProfile, ServiceError> {
        // TODO: set locale to en_US
        self.http_request(
            Method::GET,
            Self::retrieve_versioned_profile_and_credential_path(
                address,
                profile_key,
                credential_request,
            )?,
        )?
        .header(
            "Unidentified-Access-Key",
            BASE64_RELAXED.encode(&access.key),
        )
        .await?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }

    pub async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.unidentified_push_service.get_from_cdn(0, path).await
    }

    pub async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.unidentified_push_service.get_from_cdn(0, path).await
    }
}
