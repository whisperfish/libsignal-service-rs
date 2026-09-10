use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
};
use prost::Message;

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::{
    push_service::ServiceError,
    websocket::{self, SignalWebSocket},
};

/// Handle for acknowledging an envelope back to the Signal server.
///
/// Take this handle out of [`Incoming::Envelope`] and either:
///
/// * **Call [`AckHandle::ack`]** to acknowledge immediately - the server
///   removes the envelope from its queue.  This is useful when you want to
///   ack before the end of the scope (e.g. after a quick validation).
/// * **Move the handle into a future or closure** and let it drop later;
///   on drop it will auto-acknowledge.  If the thread is panicking when
///   the handle drops, the envelope is *not* acknowledged and will be
///   re-delivered by the server on the next connection.
#[derive(Debug)]
pub struct AckHandle(
    Option<(
        oneshot::Sender<WebSocketResponseMessage>,
        WebSocketResponseMessage,
    )>,
);

impl AckHandle {
    /// Acknowledge this envelope immediately.
    ///
    /// Acknowledge the envelope immediately, before the handle would
    /// otherwise be dropped.  Useful when you want to signal the server
    /// early (e.g. after a quick validation) and don't need to defer
    /// the ack to end-of-scope.
    ///
    /// Equivalent with `drop(AckHandle)`.
    pub fn ack(self) {}
}

impl Drop for AckHandle {
    fn drop(&mut self) {
        let Some((responder, response)) = self.0.take() else {
            return; // ack() was already called
        };
        if std::thread::panicking() {
            tracing::warn!(
                "AckHandle dropped during a panic; envelope NOT acknowledged, \
                 server will re-deliver"
            );
            // responder + response dropped without sending → no ack
        } else {
            let _ = responder.send(response);
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    Envelope { envelope: Envelope, ack: AckHandle },
    QueueEmpty,
}

pub struct MessagePipe {
    ws: SignalWebSocket<websocket::Identified>,
}

impl MessagePipe {
    pub fn from_socket(ws: SignalWebSocket<websocket::Identified>) -> Self {
        MessagePipe { ws }
    }

    /// Return a SignalWebSocket for sending messages and other purposes beyond receiving messages.
    pub fn ws(&self) -> SignalWebSocket<websocket::Identified> {
        self.ws.clone()
    }

    /// Worker task that processes the websocket into Envelopes
    async fn run(
        mut self,
        mut sink: Sender<Result<Incoming, ServiceError>>,
    ) -> Result<(), mpsc::SendError> {
        let mut ws = self.ws.clone();
        let mut stream = ws
            .take_request_stream()
            .expect("web socket request handler not in use");

        while let Some((request, responder)) = stream.next().await {
            // WebsocketConnection::onMessage(ByteString)
            if let Some(env) =
                self.process_request(request, responder).await.transpose()
            {
                sink.send(env).await?;
            } else {
                tracing::trace!("got empty message in websocket");
            }
        }

        ws.return_request_stream(stream);

        Ok(())
    }

    /// Process a single request from the Signal web socket.
    ///
    /// * For **envelope** requests, the response (ack) is pre-built and
    ///   stored in an [`AckHandle`] so the caller can decide when to
    ///   send it.
    /// * For **QueueEmpty** and other requests, the ack is sent
    ///   immediately, matching the old behaviour.
    async fn process_request(
        &mut self,
        request: WebSocketRequestMessage,
        responder: oneshot::Sender<WebSocketResponseMessage>,
    ) -> Result<Option<Incoming>, ServiceError> {
        // Java: MessagePipe::read
        let response = WebSocketResponseMessage::from_request(&request);

        if request.is_signal_service_envelope() {
            let body = if let Some(body) = request.body.as_ref() {
                body
            } else {
                return Err(ServiceError::InvalidFrame {
                    reason: "request without body.",
                });
            };
            let envelope = Envelope::decode(body.as_slice())?;
            let ack = AckHandle(Some((responder, response)));
            Ok(Some(Incoming::Envelope { envelope, ack }))
        } else if request.is_queue_empty() {
            let _ = responder.send(response);
            Ok(Some(Incoming::QueueEmpty))
        } else {
            // Unknown request type; ack anyway so the server knows
            // we processed it, even though we can't handle it.
            tracing::warn!(
                "Unknown request on message pipe: {} {}",
                request.verb.as_deref().unwrap_or("?"),
                request.path.as_deref().unwrap_or("?"),
            );
            let _ = responder.send(response);
            Ok(None)
        }
    }

    /// Returns a stream of incoming envelopes.
    ///
    /// Envelopes are accompanied by an [`AckHandle`] that may be used
    /// to acknowledge the envelope explicitly before the end of the
    /// enclosing scope.  See [`AckHandle`] for details on auto-ack
    /// versus panic behaviour.
    pub fn stream(self) -> impl Stream<Item = Result<Incoming, ServiceError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|e| {
            tracing::info!("sink was closed: {:?}", e);
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}
