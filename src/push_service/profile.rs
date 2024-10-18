use libsignal_protocol::Aci;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zkgroup::profiles::{ProfileKeyCommitment, ProfileKeyVersion};

use crate::{
    configuration::Endpoint,
    content::ServiceError,
    profile_cipher::ProfileCipherError,
    push_service::{AvatarWrite, HttpAuthOverride},
    utils::{serde_base64, serde_optional_base64},
    Profile,
};

use super::{DeviceCapabilities, PushService};

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

impl SignalServiceProfile {
    pub fn decrypt(
        &self,
        profile_cipher: crate::profile_cipher::ProfileCipher,
    ) -> Result<Profile, ProfileCipherError> {
        // Profile decryption
        let name = self
            .name
            .as_ref()
            .map(|data| profile_cipher.decrypt_name(data))
            .transpose()?
            .flatten();
        let about = self
            .about
            .as_ref()
            .map(|data| profile_cipher.decrypt_about(data))
            .transpose()?;
        let about_emoji = self
            .about_emoji
            .as_ref()
            .map(|data| profile_cipher.decrypt_emoji(data))
            .transpose()?;

        Ok(Profile {
            name,
            about,
            about_emoji,
            avatar: self.avatar.clone(),
        })
    }
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

impl PushService {
    pub async fn retrieve_profile_by_id(
        &mut self,
        address: Aci,
        profile_key: Option<zkgroup::profiles::ProfileKey>,
    ) -> Result<SignalServiceProfile, ServiceError> {
        let uuid: Uuid = address.into();
        let endpoint = if let Some(key) = profile_key {
            let version =
                bincode::serialize(&key.get_profile_key_version(address))?;
            let version = std::str::from_utf8(&version)
                .expect("hex encoded profile key version");
            format!("/v1/profile/{}/{}", uuid, version)
        } else {
            format!("/v1/profile/{}", uuid)
        };
        // TODO: set locale to en_US
        self.get_json(
            Endpoint::Service,
            &endpoint,
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    pub async fn retrieve_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.get_from_cdn(0, path).await
    }

    pub async fn retrieve_groups_v2_profile_avatar(
        &mut self,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        self.get_from_cdn(0, path).await
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
        let response: Result<String, _> = self
            .put_json(
                Endpoint::Service,
                "/v1/profile",
                &[],
                HttpAuthOverride::NoOverride,
                command,
            )
            .await;
        match (response, avatar) {
            (Ok(_url), AvatarWrite::NewAvatar(_avatar)) => {
                // FIXME
                unreachable!("Uploading avatar unimplemented");
            },
            // FIXME cleanup when #54883 is stable and MSRV:
            // or-patterns syntax is experimental
            // see issue #54883 <https://github.com/rust-lang/rust/issues/54883> for more information
            (
                Err(ServiceError::JsonDecodeError { .. }),
                AvatarWrite::RetainAvatar,
            )
            | (
                Err(ServiceError::JsonDecodeError { .. }),
                AvatarWrite::NoAvatar,
            ) => {
                // OWS sends an empty string when there's no attachment
                Ok(None)
            },
            (Err(e), _) => Err(e),
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
