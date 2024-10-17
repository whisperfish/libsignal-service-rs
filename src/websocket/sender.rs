use crate::{
    sender::{OutgoingPushMessages, SendMessageResponse},
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};

use super::*;
use base64::Engine;

impl SignalWebSocket {
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(format!("/v1/messages/{}", messages.destination))
            .json(&messages)?;
        self.request_json(request).await
    }

    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        let request = WebSocketRequestMessage::new(Method::PUT)
            .path(format!("/v1/messages/{}", messages.destination))
            .header(
                "Unidentified-Access-Key:{}",
                BASE64_RELAXED.encode(&access.key),
            )
            .json(&messages)?;
        self.request_json(request).await
    }
}
