use reqwest::Method;
use serde::Serialize;

use crate::proto::WebSocketRequestMessage;

#[derive(Debug)]
pub struct WebSocketRequestMessageBuilder {
    request: WebSocketRequestMessage,
}

impl WebSocketRequestMessage {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(method: Method) -> WebSocketRequestMessageBuilder {
        WebSocketRequestMessageBuilder {
            request: WebSocketRequestMessage {
                verb: Some(method.to_string()),
                ..Default::default()
            },
        }
    }
}

impl WebSocketRequestMessageBuilder {
    pub fn id(mut self, id: u64) -> Self {
        self.request.id = Some(id);
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.request.path = Some(path.into());
        self
    }

    pub fn header(mut self, key: &str, value: impl AsRef<str>) -> Self {
        self.request
            .headers
            .push(format!("{key}={}", value.as_ref()));
        self
    }

    pub fn json<S: Serialize>(
        mut self,
        value: S,
    ) -> Result<WebSocketRequestMessage, serde_json::Error> {
        self.request.body = Some(serde_json::to_vec(&value)?);
        Ok(self.header("Content-Type", "application/json").request)
    }

    pub fn build(self) -> WebSocketRequestMessage {
        self.request
    }
}
