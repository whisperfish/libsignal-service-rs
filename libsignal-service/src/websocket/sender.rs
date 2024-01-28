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
        let path = format!("/v1/messages/{}", messages.recipient.uuid);
        self.put_json(&path, messages).await
    }

    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.recipient.uuid);
        let header = format!(
            "Unidentified-Access-Key:{}",
            BASE64_RELAXED.encode(&access.key)
        );
        self.put_json_with_headers(&path, messages, vec![header])
            .await
    }
}
