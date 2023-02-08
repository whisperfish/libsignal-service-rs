use crate::sender::{OutgoingPushMessages, SendMessageResponse};

use super::*;

impl SignalWebSocket {
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.recipient.uuid);
        self.put_json(&path, messages).await
    }
}
