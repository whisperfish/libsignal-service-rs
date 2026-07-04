use crate::{
    push_service::{response::error_mapper, SendMultiRecipientMessageResponse},
    sender::{
        MultiRecipientMessagesRequest, OutgoingPushMessages,
        SendMessageResponse,
    },
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};

use super::*;
use base64::Engine;

error_mapper! {
    PutMessages:
        CONFLICT => MismatchedDevicesException(crate::push_service::MismatchedDevices),
        GONE => StaleDevices(crate::push_service::StaleDevices),
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        NOT_FOUND => UnregisteredRecipient,
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

error_mapper! {
    PutMultiRecipientMessages:
        CONFLICT => MultiRecipientMismatchedDevices(Vec<crate::push_service::AccountMismatchedDevices>),
        GONE => MultiRecipientStaleDevices(Vec<crate::push_service::AccountStaleDevices>),
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

/// Media type for the Sealed Sender v2 multi-recipient payload.
///
/// Matches `MultiRecipientMessageProvider.MEDIA_TYPE` on the server. Only the
/// raw bytes (as produced by `libsignal_protocol::sealed_sender_multi_recipient_encrypt`)
/// are sent; the server re-parses and fans out per recipient.
const MULTI_RECIPIENT_MEDIA_TYPE: &str = "application/vnd.signal-messenger.mrm";

impl<C: WebSocketType> SignalWebSocket<C> {
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
        self.request_json::<_, PutMessages>(request).await
    }

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
        self.request_json::<_, PutMessages>(request).await
    }

    /// `PUT /v1/messages/multi_recipient`: deliver a single Sealed Sender v2
    /// multi-recipient payload to all of its recipients.
    ///
    /// The body content type is [`MULTI_RECIPIENT_MEDIA_TYPE`] and the body is
    /// the raw bytes returned by
    /// `libsignal_protocol::sealed_sender_multi_recipient_encrypt` — the
    /// server re-parses the multi-recipient message and fans it out per
    /// recipient.
    ///
    /// `request.access` sets the authorization header per the
    /// [`MultiRecipientAccess`] variant; pass `None` for stories. The 200
    /// response lists any group-send-endorsement recipients the server could not
    /// resolve as registered users.
    ///
    /// `409`/`410` become [`ServiceError::MultiRecipientMismatchedDevices`] /
    /// [`ServiceError::MultiRecipientStaleDevices`] respectively, rather than
    /// the single-recipient variants decoded by
    /// [`SignalWebSocket::send_messages`].
    pub async fn send_multi_recipient_messages(
        &mut self,
        request: MultiRecipientMessagesRequest<'_>,
    ) -> Result<SendMultiRecipientMessageResponse, ServiceError> {
        let MultiRecipientMessagesRequest {
            timestamp,
            online,
            urgent,
            story,
            payload,
            access,
        } = request;

        // Match the query-parameter form used by the Java client
        // (GROUP_MESSAGE_PATH /v1/messages/multi_recipient?ts=...&online=...&urgent=...&story=...).
        let path = format!(
            "/v1/messages/multi_recipient?ts={timestamp}&online={online}&urgent={urgent}&story={story}"
        );

        let mut builder = WebSocketRequestMessage::new(Method::PUT).path(path);
        if let Some(access) = access.as_ref() {
            let (name, value) = access.header();
            builder = builder.header(name, value);
        }
        let request =
            builder.body(MULTI_RECIPIENT_MEDIA_TYPE, payload.to_vec());

        self.request_json::<_, PutMultiRecipientMessages>(request)
            .await
    }
}
