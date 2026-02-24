use crate::utils::serde_base64;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libsignal_core::{Aci, ServiceIdKind};
use reqwest::Method;

use crate::content::ServiceError;

use super::{SignalWebSocket, Unidentified};

impl SignalWebSocket<Unidentified> {
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

    // Based on libsignal-net
    pub async fn look_up_username_link(
        &mut self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, ServiceError> {
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde(with = "serde_base64")]
            encrypted_username: Vec<u8>,
        }

        let response = self
            .http_request(
                Method::GET,
                format!("/v1/accounts/username_link/{uuid}",),
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
            usernames::decrypt_username(entropy, &result.encrypted_username)
                .map_err(|_e| {
                    tracing::error!(error=%_e, "undecryptable username");
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
