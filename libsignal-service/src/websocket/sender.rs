use crate::sender::{OutgoingPushMessages, SendMessageResponse};

use super::*;

impl SignalWebSocket {
    pub async fn send_messages<'a>(
        &mut self,
        messages: OutgoingPushMessages<'a>,
    ) -> Result<SendMessageResponse, ServiceError> {
        let path = format!("/v1/messages/{}", messages.destination);
        self.put_json(&path, messages).await
    }
}
