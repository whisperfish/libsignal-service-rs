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
/// Take this handle out of [`Incoming::Envelope`] and call [`AckHandle::ack`]
/// once the envelope is handled (its message stored, say): the server then
/// removes the envelope from its queue.
///
/// A handle dropped without that answers the server with an error (500): the
/// server keeps the envelope and delivers it again on the next connection, so
/// an envelope whose handling failed or was cut short, by a panic or by its
/// task being dropped (a process ending, an aborted task), isn't lost.  An
/// answer it does need: the server says the queue is empty only once every
/// envelope before is answered, and sends nothing more with 256 unanswered
/// (Signal-Server `WebSocketConnection`), as Signal-Desktop answers 500 too.
#[derive(Debug)]
pub struct AckHandle(
    Option<(
        oneshot::Sender<WebSocketResponseMessage>,
        WebSocketResponseMessage,
    )>,
);

impl AckHandle {
    /// Acknowledge this envelope: the server removes it from its queue.
    pub fn ack(mut self) {
        if let Some((responder, response)) = self.0.take() {
            let _ = responder.send(response);
        }
    }
}

/// The answer for an envelope that wasn't handled: the server keeps it.
fn not_handled(id: Option<u64>) -> WebSocketResponseMessage {
    WebSocketResponseMessage {
        id,
        status: Some(500),
        message: Some("Internal Server Error".to_string()),
        ..Default::default()
    }
}

impl Drop for AckHandle {
    fn drop(&mut self) {
        if let Some((responder, response)) = self.0.take() {
            tracing::debug!("envelope dropped unacknowledged; the server will deliver it again");
            let _ = responder.send(not_handled(response.id));
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
            // One that can't be read is answered too, or it holds the queue back.
            let body = if let Some(body) = request.body.as_ref() {
                body
            } else {
                let _ = responder.send(not_handled(request.id));
                return Err(ServiceError::InvalidFrame {
                    reason: "request without body.",
                });
            };
            let envelope = match Envelope::decode(body.as_slice()) {
                Ok(envelope) => envelope,
                Err(error) => {
                    let _ = responder.send(not_handled(request.id));
                    return Err(error.into());
                },
            };
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
    /// Envelopes are accompanied by an [`AckHandle`], to acknowledge each
    /// once it is handled; one dropped unacknowledged is delivered again.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle, and what the websocket would send the server for it.
    fn handle() -> (AckHandle, oneshot::Receiver<WebSocketResponseMessage>) {
        let (responder, acked) = oneshot::channel();
        let ack =
            AckHandle(Some((responder, WebSocketResponseMessage::default())));
        (ack, acked)
    }

    /// A receiving task dropped while it handles an envelope, as when a process returns from
    /// `main` or a client aborts its receive task, hasn't handled it: the server must deliver
    /// it again, and hear that it wasn't, so that the queue moves on.
    #[tokio::test]
    async fn a_task_dropped_while_handling_leaves_the_envelope_unacknowledged()
    {
        let (ack, acked) = handle();
        let handling = tokio::spawn(async move {
            let _ack = ack;
            // Storing the message, say.
            futures::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        handling.abort();
        assert!(handling.await.unwrap_err().is_cancelled());
        let answer = acked.await.expect("answered");
        assert_eq!(
            answer.status,
            Some(500),
            "acknowledged an envelope that was never handled"
        );
    }

    #[tokio::test]
    async fn ack_acknowledges() {
        let (ack, acked) = handle();
        ack.ack();
        assert!(acked.await.is_ok());
    }
}
