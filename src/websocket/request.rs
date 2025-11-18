use std::fmt;

use reqwest::Method;
use serde::Serialize;

use crate::{
    content::ServiceError,
    proto::{WebSocketRequestMessage, WebSocketResponseMessage},
    websocket::{SignalWebSocket, WebSocketType},
};

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
            .push(format!("{key}:{}", value.as_ref()));
        self
    }

    pub fn json<S: Serialize>(
        mut self,
        value: S,
    ) -> Result<WebSocketRequestMessage, serde_json::Error> {
        self.request.body = Some(serde_json::to_vec(&value)?);
        Ok(self.header("content-type", "application/json").request)
    }

    pub fn build(self) -> WebSocketRequestMessage {
        self.request
    }
}

pub(crate) struct WebSocketRequestBuilder<'a, C: WebSocketType> {
    ws: &'a mut SignalWebSocket<C>,
    message_builder: WebSocketRequestMessageBuilder,
}

impl<C: WebSocketType> SignalWebSocket<C> {
    #[tracing::instrument(skip(self))]
    pub(crate) fn http_request(
        &mut self,
        method: Method,
        path: impl Into<String> + fmt::Debug,
    ) -> Result<WebSocketRequestBuilder<'_, C>, ServiceError> {
        Ok(WebSocketRequestBuilder {
            ws: self,
            message_builder: WebSocketRequestMessage::new(method).path(path),
        })
    }
}

impl<C: WebSocketType> WebSocketRequestBuilder<'_, C> {
    pub(crate) async fn send_json<B: Serialize>(
        self,
        value: B,
    ) -> Result<WebSocketResponseMessage, ServiceError> {
        let request = self.message_builder.json(value)?;
        self.ws.request(request).await
    }

    pub(crate) async fn send(
        self,
    ) -> Result<WebSocketResponseMessage, ServiceError> {
        let request = self.message_builder.build();
        self.ws.request(request).await
    }
}
