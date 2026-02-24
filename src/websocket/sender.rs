use super::*;
use crate::{
    groups_v2::GroupSendToken,
    sender::{OutgoingPushMessages, SendMessageResponse},
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};
use base64::Engine;

/// Response from the multi-recipient send endpoint.
#[derive(Debug)]
pub struct MultiRecipientSendResult {
    /// Service IDs that were not found (404 responses).
    pub unregistered_service_ids: Vec<libsignal_core::ServiceId>,
}

impl<C: WebSocketType> SignalWebSocket<C> {
    // =========================================================================
    // SINGLE-RECIPIENT METHODS (for 1-to-1 messages)
    // =========================================================================

    /// Send messages to a single recipient with standard authentication.
    ///
    /// This is the original method for identified (non-anonymous) messaging.
    /// Use for 1-to-1 messages when the recipient doesn't have an access key.
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(format!(
                "/v1/messages/{}",
                messages.destination.service_id_string()
            ))
            .json(&messages)?;
        self.request_json(request).await
    }

    /// Send messages to a single recipient with unidentified access.
    ///
    /// This uses the `Unidentified-Access-Key` header for anonymous delivery.
    /// Used for 1-to-1 messages when the recipient has a profile key.
    ///
    /// **Backwards compatibility:** This method is kept for 1-to-1 messages.
    /// For group messages, prefer `send_multi_recipient_with_token`.
    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(format!(
                "/v1/messages/{}",
                messages.destination.service_id_string()
            ))
            .header(
                "Unidentified-Access-Key",
                BASE64_RELAXED.encode(&access.key),
            )
            .json(&messages)?;
        self.request_json(request).await
    }

    // =========================================================================
    // MULTI-RECIPIENT METHODS (for group messages with GSE)
    // =========================================================================

    /// Send a multi-recipient message using a Group Send Token.
    ///
    /// This uses the `/v1/messages/multi_recipient` endpoint with the `Group-Send-Token`
    /// header. This is the modern, efficient way to send to multiple group members
    /// in a single request with anonymous delivery.
    ///
    /// The message payload must be encrypted using sealed sender multi-recipient
    /// encryption before calling this method.
    ///
    /// # Arguments
    ///
    /// * `payload` - The encrypted multi-recipient message payload
    /// * `token` - The group send endorsement token
    /// * `timestamp` - The message timestamp
    /// * `online` - Whether to deliver immediately to online recipients
    /// * `urgent` - Whether this message is time-sensitive
    ///
    /// # Returns
    ///
    /// Returns `Ok` with a list of unregistered service IDs on success (HTTP 200),
    /// or an error on failure.
    pub async fn send_multi_recipient_with_token(
        &mut self,
        payload: &[u8],
        token: &GroupSendToken,
        timestamp: u64,
        online: bool,
        urgent: bool,
    ) -> Result<MultiRecipientSendResult, ServiceError> {
        let path = format!(
            "/v1/messages/multi_recipient?ts={}&online={}&urgent={}",
            timestamp, online, urgent
        );

        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(&path)
            .header("Group-Send-Token", token.to_base64())
            .body(payload.to_vec());

        let response = self.request(request).await?;
        let status = response.status();

        // Handle 200 response
        if status == 200 {
            return self.parse_multi_recipient_response(response).await;
        }

        Err(ServiceError::UnhandledResponseCode {
            http_code: status as u16,
        })
    }

    /// Send a multi-recipient message with legacy XOR'd access keys.
    ///
    /// This uses the `/v1/messages/multi_recipient` endpoint with the
    /// `Unidentified-Access-Key` header. The access key should be the XOR of
    /// all recipients' access keys.
    ///
    /// **Deprecated:** Prefer `send_multi_recipient_with_token` when group send
    /// endorsements are available. This method is kept for backwards compatibility
    /// with older servers or when endorsements are not available.
    pub async fn send_multi_recipient_with_access_key(
        &mut self,
        payload: &[u8],
        access_key: &[u8],
        timestamp: u64,
        online: bool,
        urgent: bool,
    ) -> Result<MultiRecipientSendResult, ServiceError> {
        let path = format!(
            "/v1/messages/multi_recipient?ts={}&online={}&urgent={}",
            timestamp, online, urgent
        );

        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(&path)
            .header(
                "Unidentified-Access-Key",
                BASE64_RELAXED.encode(access_key),
            )
            .body(payload.to_vec());

        let response = self.request(request).await?;
        let status = response.status();

        // Handle 200 response
        if status == 200 {
            return self.parse_multi_recipient_response(response).await;
        }

        Err(ServiceError::UnhandledResponseCode {
            http_code: status as u16,
        })
    }

    /// Parse the response from the multi-recipient endpoint.
    async fn parse_multi_recipient_response(
        &self,
        response: WebSocketResponseMessage,
    ) -> Result<MultiRecipientSendResult, ServiceError> {
        let body = response.body.unwrap_or_default();

        if body.is_empty() {
            return Ok(MultiRecipientSendResult {
                unregistered_service_ids: vec![],
            });
        }

        // Parse JSON response like: {"uuids404": [...], "needsSync": false}
        #[derive(serde::Deserialize)]
        struct MultiRecipientResponse {
            #[serde(default)]
            uuids404: Vec<String>,
        }

        let parsed: MultiRecipientResponse = serde_json::from_slice(&body)?;

        let unregistered_service_ids = parsed
            .uuids404
            .into_iter()
            .filter_map(|s| {
                libsignal_core::ServiceId::parse_from_service_id_string(&s)
            })
            .collect();

        Ok(MultiRecipientSendResult {
            unregistered_service_ids,
        })
    }
}
