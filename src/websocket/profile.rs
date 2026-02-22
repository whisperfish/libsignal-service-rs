use libsignal_protocol::Aci;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use zkgroup::profiles::{
    ProfileKey, ProfileKeyCommitment, ProfileKeyCredentialRequest,
    ProfileKeyVersion,
};

use crate::{
    content::ServiceError,
    push_service::AvatarWrite,
    utils::{serde_base64, serde_optional_base64},
    websocket::{self, account::DeviceCapabilities, SignalWebSocket},
};

#[derive(Debug, Deserialize)]
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
}

/// Profile response that includes an optional expiring profile key credential.
/// Used when requesting a profile with a credential request for group operations.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalServiceProfileWithCredential {
    #[serde(flatten)]
    pub profile: SignalServiceProfile,
    /// The expiring profile key credential response, base64-encoded.
    /// This is present when the request included a valid credential request.
    /// Note: The server returns this as "credential", not "expiringProfileKeyCredential".
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

impl SignalWebSocket<websocket::Identified> {
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let path = if let Some(key) = profile_key {
            let version =
                bincode::serialize(&key.get_profile_key_version(address))?;
            let version = std::str::from_utf8(&version)
                .expect("hex encoded profile key version");
            format!("/v1/profile/{}/{}", address.service_id_string(), version)
        } else {
            format!("/v1/profile/{}", address.service_id_string())
        };
        // TODO: set locale to en_US
        self.http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }

    /// Retrieve a profile with a credential request for group operations.
    ///
    /// This method fetches the user's profile along with an `ExpiringProfileKeyCredentialResponse`
    /// that can be used to create presentations for group creation and member addition.
    ///
    /// # Arguments
    /// * `address` - The ACI of the user whose profile to fetch
    /// * `profile_key` - The profile key for the user
    /// * `credential_request` - The credential request created via `create_credential_request`
    ///
    /// # Returns
    /// A `SignalServiceProfileWithCredential` containing the profile and optional credential response.
    pub async fn retrieve_profile_with_credential(
        &mut self,
        address: Aci,
        profile_key: ProfileKey,
        credential_request: &ProfileKeyCredentialRequest,
    ) -> Result<SignalServiceProfileWithCredential, ServiceError> {
        // ProfileKeyVersion implements AsRef<str> and returns hex ASCII directly
        let version = profile_key.get_profile_key_version(address);
        let version_str: &str = version.as_ref();

        let request_hex = hex::encode(zkgroup::serialize(credential_request));

        // The credential request is a PATH parameter, not a query parameter.
        // Server route: /v1/profile/{identifier}/{version}/{credentialRequest}?credentialType=expiringProfileKey
        let path = format!(
            "/v1/profile/{}/{}/{}?credentialType=expiringProfileKey",
            address.service_id_string(),
            version_str,
            request_hex
        );

        tracing::debug!(
            %path,
            credential_request_len = request_hex.len(),
            "fetching profile with credential request"
        );

        let response = self
            .http_request(Method::GET, &path)?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        let result: SignalServiceProfileWithCredential =
            response.json().await?;

        tracing::debug!(
            has_credential = result.credential.is_some(),
            credential_len = result.credential.as_ref().map(|c| c.len()),
            "got profile response"
        );

        Ok(result)
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

        // XXX this should  be a struct; cfr ProfileAvatarUploadAttributes
        let upload_url: Result<String, _> = self
            .http_request(Method::PUT, "/v1/profile")?
            .send_json(&command)
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await;

        match (upload_url, avatar) {
            (_url, AvatarWrite::NewAvatar(_avatar)) => {
                // FIXME
                unreachable!("Uploading avatar unimplemented");
            },
            // FIXME cleanup when #54883 is stable and MSRV:
            // or-patterns syntax is experimental
            // see issue #54883 <https://github.com/rust-lang/rust/issues/54883> for more information
            (Err(_), AvatarWrite::RetainAvatar)
            | (Err(_), AvatarWrite::NoAvatar) => {
                // OWS sends an empty string when there's no attachment
                Ok(None)
            },
            (Ok(_resp), AvatarWrite::RetainAvatar)
            | (Ok(_resp), AvatarWrite::NoAvatar) => {
                tracing::warn!(
                    "No avatar supplied but got avatar upload URL. Ignoring"
                );
                Ok(None)
            },
        }
    }
}

impl SignalWebSocket<websocket::Unidentified> {
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
