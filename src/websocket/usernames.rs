use crate::utils::serde_base64_url_safe_no_pad;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;
use serde::Serialize;

use crate::content::ServiceError;

use super::{Identified, SignalWebSocket, Unidentified};

impl SignalWebSocket<Unidentified> {
    pub async fn look_up_username(
        &mut self,
        username: &usernames::Username,
    ) -> Result<Option<Aci>, ServiceError> {
        self.look_up_username_hash(&username.hash()).await
    }

    // Based on libsignal-net
    pub async fn look_up_username_hash(
        &mut self,
        hash: &[u8],
    ) -> Result<Option<Aci>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let response = self
            .http_request(
                Method::GET,
                format!(
                    "/v1/accounts/username_hash/{}",
                    BASE64_URL_SAFE_NO_PAD.encode(hash)
                ),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username not found");
            return Ok(None);
        }

        let result: UsernameHashResponse =
            response.service_error_for_status().await?.json().await?;

        Ok(Some(
            Aci::parse_from_service_id_string(&result.uuid).ok_or_else(
                || ServiceError::InvalidAddressType(ServiceIdKind::Aci),
            )?,
        ))
    }

    /// Looks up the encrypted username stored at a username link handle and
    /// decrypts it.
    ///
    /// `link` is accepted either as a full `https://signal.me/#eu/<payload>`
    /// link or as the bare `<payload>` that follows `#eu/`. The payload is the
    /// URL-safe base64 encoding of the 32-byte link entropy followed by the
    /// 16-byte link handle UUID.
    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        link: &str,
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64_url_safe_no_pad")]
            encrypted_username: Vec<u8>,
        }

        let (uuid, entropy) = parse_username_link(link)?;

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}"),
            )?
            .send()
            .await?;

        if response.status() == 404 {
            tracing::debug!("username link not found");
            return Ok(None);
        }

        let result: UsernameLinkResponse =
            response.service_error_for_status().await?.json().await?;

        let plaintext_username =
            usernames::decrypt_username(&entropy, &result.encrypted_username)
                .map_err(|error| {
                tracing::error!(%error, "undecryptable username");
                ServiceError::InvalidFrame {
                    reason: "undecryptable username link",
                }
            })?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            #[allow(clippy::let_unit_value)]
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            tracing::warn!(error=%e, "username link decrypted to an invalid username");
            tracing::debug!(error=%e,
                "username link decrypted to '{plaintext_username}', which is not valid"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            ServiceError::InvalidFrame {
                reason: "undecryptable username link",
            }
        })?;

        Ok(Some(validated_username))
    }
}

/// Splits a username link into its link handle UUID and link entropy.
///
/// Accepts either a full `https://signal.me/#eu/<payload>` link or the bare
/// `<payload>` after `#eu/`. The payload is URL-safe base64 (no padding) of
/// the 32-byte entropy followed by the 16-byte handle UUID.
fn parse_username_link(
    link: &str,
) -> Result<
    (
        uuid::Uuid,
        [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ),
    ServiceError,
> {
    let payload = link
        .rsplit_once("#eu/")
        .map(|(_, payload)| payload)
        .unwrap_or(link);

    let bytes = BASE64_URL_SAFE_NO_PAD.decode(payload)?;

    let (entropy, rest) = bytes
        .split_first_chunk::<{ usernames::constants::USERNAME_LINK_ENTROPY_SIZE }>()
        .ok_or_else(|| ServiceError::InvalidFrame {
            reason: "username link payload shorter than entropy",
        })?;

    let handle_uuid = uuid::Uuid::from_slice(rest).map_err(|_| {
        ServiceError::InvalidFrame {
            reason: "username link payload missing handle UUID",
        }
    })?;

    Ok((handle_uuid, *entropy))
}

impl SignalWebSocket<Identified> {
    /// Sets the account's username link to encrypt `username` and returns the
    /// shareable `https://signal.me/#eu/...` link.
    ///
    /// Generates fresh entropy and, unless `keep_link_handle` is `true` and the
    /// account already has a link handle, a fresh server-assigned handle.
    // Based on libsignal-net
    pub async fn set_username_link(
        &mut self,
        username: &usernames::Username,
        keep_link_handle: bool,
    ) -> Result<String, ServiceError> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SetUsernameLinkRequest {
            #[serde(with = "serde_base64_url_safe_no_pad")]
            username_link_encrypted_value: Vec<u8>,
            keep_link_handle: bool,
        }

        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UsernameLinkHandleResponse {
            username_link_handle: uuid::Uuid,
        }

        let (entropy, ciphertext) = usernames::create_for_username(
            &mut rand::rng(),
            username.to_string(),
            None,
        )
        .map_err(|_e| ServiceError::InvalidFrame {
            reason: "username too long to encrypt",
        })?;

        let response = self
            .http_request(Method::PUT, "/v1/accounts/username_link")?
            .send_json(SetUsernameLinkRequest {
                username_link_encrypted_value: ciphertext,
                keep_link_handle,
            })
            .await?
            .service_error_for_status()
            .await?;

        let result: UsernameLinkHandleResponse = response.json().await?;

        Ok(generate_username_link(
            result.username_link_handle,
            &entropy,
        ))
    }
}

/// Builds the `https://signal.me/#eu/<base64url>` link from its parts.
///
/// `entropy` is the 32-byte link entropy; `handle` is the server-assigned
/// link handle UUID. The payload is the URL-safe base64 (no padding) of
/// `entropy || handle`.
pub fn generate_username_link(
    handle: uuid::Uuid,
    entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
) -> String {
    let mut payload = entropy.to_vec();
    payload.extend_from_slice(handle.as_bytes());
    format!(
        "https://signal.me/#eu/{}",
        BASE64_URL_SAFE_NO_PAD.encode(&payload)
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generate_and_parse_link_round_trip() {
        let entropy = [0x42; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
        // deliberately chosen to round-trip cleanly through URL-safe base64
        let link = generate_username_link(handle, &entropy);
        assert!(link.starts_with("https://signal.me/#eu/"));

        let (parsed_handle, parsed_entropy) =
            parse_username_link(&link).unwrap();
        assert_eq!(parsed_handle, handle);
        assert_eq!(parsed_entropy, entropy);
    }

    #[test]
    fn parse_link_accepts_bare_payload() {
        let entropy = [0x11; usernames::constants::USERNAME_LINK_ENTROPY_SIZE];
        let handle = uuid::uuid!("00000000-0000-0000-0000-000000000000");
        let link = generate_username_link(handle, &entropy);
        let payload = link.rsplit_once("#eu/").unwrap().1;
        let (parsed_handle, parsed_entropy) =
            parse_username_link(payload).unwrap();
        assert_eq!(parsed_handle, handle);
        assert_eq!(parsed_entropy, entropy);
    }
}
