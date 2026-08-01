use crate::{
    push_service::response::error_mapper,
    sender::{OutgoingPushMessages, SendMessageResponse},
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
    #[allow(dead_code)]
    PutMultiRecipientMessages:
        CONFLICT => MultiRecipientMismatchedDevices(Vec<crate::push_service::AccountMismatchedDevices>),
        GONE => MultiRecipientStaleDevices(Vec<crate::push_service::AccountStaleDevices>),
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        PRECONDITION_REQUIRED => ProofRequiredError(crate::push_service::ProofRequired),
}

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
}
