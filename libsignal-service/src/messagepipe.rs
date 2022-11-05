use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
    stream::FusedStream,
};

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::{push_service::ServiceError, websocket::SignalWebSocket};

pub enum WebSocketStreamItem {
    Message(Bytes),
    KeepAliveRequest,
}

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
pub trait WebSocketService {
    type Stream: FusedStream<Item = WebSocketStreamItem> + Unpin;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError>;
}

pub struct MessagePipe {
    ws: SignalWebSocket,
    credentials: ServiceCredentials,
}

impl MessagePipe {
    pub fn from_socket(
        ws: SignalWebSocket,
        credentials: ServiceCredentials,
    ) -> Self {
        MessagePipe { ws, credentials }
    }

    /// Return a SignalWebSocket for sending messages and other purposes beyond receiving messages.
    pub fn ws(&self) -> SignalWebSocket {
        self.ws.clone()
    }

    /// Worker task that processes the websocket into Envelopes
    async fn run(
        mut self,
        mut sink: Sender<Result<Envelope, ServiceError>>,
    ) -> Result<(), mpsc::SendError> {
        let mut ws = self.ws.clone();
        let mut stream = ws
            .take_request_stream()
            .expect("web socket request handler not in use");

        while let Some((request, responder)) = stream.next().await {
            // WebsocketConnection::onMessage(ByteString)
            let env =
                self.process_request(request, responder).await.transpose();
            if let Some(env) = env {
                sink.send(env).await?;
            }
        }

        ws.return_request_stream(stream);

        Ok(())
    }

    async fn process_request(
        &mut self,
        request: WebSocketRequestMessage,
        responder: oneshot::Sender<WebSocketResponseMessage>,
    ) -> Result<Option<Envelope>, ServiceError> {
        // Java: MessagePipe::read
        let response = WebSocketResponseMessage::from_request(&request);

        // XXX Change the signature of this method to yield an enum of Envelope and EndOfQueue
        let result = if request.is_signal_service_envelope() {
            let body = if let Some(body) = request.body.as_ref() {
                body
            } else {
                return Err(ServiceError::InvalidFrameError {
                    reason: "Request without body.".into(),
                });
            };
            Some(Envelope::decrypt(
                body,
                self.credentials
                    .signaling_key
                    .as_ref()
                    .expect("signaling_key required to decrypt envelopes"),
                request.is_signal_key_encrypted(),
            )?)
        } else {
            None
        };

        responder
            .send(response)
            .map_err(|_| ServiceError::WsClosing {
                reason: "could not respond to message pipe request".into(),
            })?;

        Ok(result)
    }

    /// Returns the stream of `Envelope`s
    ///
    /// Envelopes yielded are acknowledged.
    pub fn stream(self) -> impl Stream<Item = Result<Envelope, ServiceError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|e| {
            log::info!("Sink was closed. Reason: {:?}", e);
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}

/// WebSocketService that panics on every request, mainly for example code.
pub struct PanicingWebSocketService;

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
impl WebSocketService for PanicingWebSocketService {
    type Stream = futures::channel::mpsc::Receiver<WebSocketStreamItem>;

    async fn send_message(&mut self, _msg: Bytes) -> Result<(), ServiceError> {
        unimplemented!();
    }
}
