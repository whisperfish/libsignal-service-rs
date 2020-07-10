use bytes::{Bytes, BytesMut};
use futures::{
    channel::mpsc::{self, Sender},
    prelude::*,
};
use pin_project::pin_project;
use prost::Message;

pub use crate::{
    configuration::Credentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
    push_service::ServiceError,
};

#[async_trait::async_trait(?Send)]
pub trait WebSocketService {
    type Stream: Stream<Item = Bytes> + Unpin;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError>;
}

#[pin_project]
pub struct MessagePipe<WS: WebSocketService> {
    ws: WS,
    #[pin]
    stream: WS::Stream,
    credentials: Credentials,
}

impl<WS: WebSocketService> MessagePipe<WS> {
    pub fn from_socket(
        ws: WS,
        stream: WS::Stream,
        credentials: Credentials,
    ) -> Self {
        MessagePipe {
            ws,
            stream,
            credentials,
        }
    }

    async fn send_response(
        &mut self,
        r: WebSocketResponseMessage,
    ) -> Result<(), ServiceError> {
        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response.into()),
            response: Some(r),
            ..Default::default()
        };
        let mut buffer = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buffer).unwrap();
        self.ws.send_message(buffer.into()).await
    }

    /// Worker task that
    async fn run(
        mut self,
        mut sink: Sender<Result<Envelope, ServiceError>>,
    ) -> Result<(), mpsc::SendError> {
        while let Some(frame) = self.stream.next().await {
            // WebsocketConnection::onMessage(ByteString)
            let msg = match WebSocketMessage::decode(frame) {
                Ok(msg) => msg,
                Err(e) => {
                    sink.send(Err(e.into())).await?;
                    continue;
                },
            };

            log::trace!("Decoded {:?}", msg);

            use web_socket_message::Type;
            match (msg.r#type(), msg.request) {
                (Type::Unknown, _) => {
                    sink.send(Err(ServiceError::InvalidFrameError {
                        reason: "Unknown frame type".into(),
                    }))
                    .await?;
                },
                (Type::Request, Some(request)) => {
                    // Java: MessagePipe::read
                    let response =
                        WebSocketResponseMessage::from_request(&request);

                    if request.is_signal_service_envelope() {
                        let body = if let Some(body) = request.body.as_ref() {
                            body
                        } else {
                            sink.send(Err(ServiceError::InvalidFrameError {
                                reason: "Request without body.".into(),
                            }))
                            .await?;
                            continue;
                        };
                        let envelope = Envelope::decrypt(
                            body,
                            &self.credentials.signaling_key,
                            request.is_signal_key_encrypted(),
                        );
                        sink.send(envelope.map_err(Into::into)).await?;
                    }

                    if let Err(e) = self.send_response(response).await {
                        sink.send(Err(e)).await?;
                    }
                },
                (Type::Request, None) => {
                    sink.send(Err(ServiceError::InvalidFrameError {
                        reason:
                            "Type was request, but does not contain request."
                                .into(),
                    }))
                    .await?;
                },
                (Type::Response, _) => {},
            }
        }
        Ok(())
    }

    /// Returns the stream of `Envelope`s
    pub fn stream(self) -> impl Stream<Item = Result<Envelope, ServiceError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|_| {
            log::info!("Sink was closed.");
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}

/// WebSocketService that panics on every request, mainly for example code.
pub struct PanicingWebSocketService;

#[async_trait::async_trait(?Send)]
impl WebSocketService for PanicingWebSocketService {
    type Stream = futures::channel::mpsc::Receiver<Bytes>;

    async fn send_message(&mut self, _msg: Bytes) -> Result<(), ServiceError> {
        unimplemented!();
    }
}
