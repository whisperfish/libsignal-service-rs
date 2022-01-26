use std::collections::HashMap;

use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
    stream::{FusedStream, FuturesUnordered},
};
use pin_project::pin_project;
use prost::Message;

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::push_service::ServiceError;

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

#[pin_project]
pub struct MessagePipe<WS: WebSocketService> {
    ws: WS,
    #[pin]
    stream: WS::Stream,
    credentials: ServiceCredentials,
    requests: HashMap<u64, oneshot::Sender<WebSocketResponseMessage>>,
}

impl<WS: WebSocketService> MessagePipe<WS> {
    pub fn from_socket(
        ws: WS,
        stream: WS::Stream,
        credentials: ServiceCredentials,
    ) -> Self {
        MessagePipe {
            ws,
            stream,
            credentials,
            requests: HashMap::new(),
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
        let buffer = msg.encode_to_vec();
        self.ws.send_message(buffer.into()).await
    }

    /// Sends a request without returning a response.
    async fn transmit_request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<(), ServiceError> {
        log::trace!("Sending request {:?}", r);
        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request.into()),
            request: Some(r),
            ..Default::default()
        };
        let buffer = msg.encode_to_vec();
        self.ws.send_message(buffer.into()).await?;
        log::trace!("request on route.");
        Ok(())
    }

    /// Send request and returns the response as a *nested* Future.
    ///
    /// The outer Future sends the request, the inner Future resolves to the
    /// response.
    pub async fn send_request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<
        impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>,
        ServiceError,
    > {
        let id = r.id;

        self.transmit_request(r).await?;

        let (sink, send) = oneshot::channel();

        if let Some(id) = id {
            self.requests.insert(id, sink);
            Ok(send.map_err(|_| ServiceError::WsClosing {
                reason: "WebSocket closing while sending request.".into(),
            }))
        } else {
            Err(ServiceError::InvalidFrameError {
                reason: "Send request without ID".into(),
            })
        }
    }

    /// Worker task that
    async fn run(
        mut self,
        mut sink: Sender<Result<Envelope, ServiceError>>,
    ) -> Result<(), mpsc::SendError> {
        use futures::future::LocalBoxFuture;

        // This is a runtime-agnostic, poor man's `::spawn(Future<Output=()>)`.
        let mut background_work = FuturesUnordered::<LocalBoxFuture<()>>::new();
        // a pending task is added, as to never end the background worker until
        // it's dropped.
        background_work.push(futures::future::pending().boxed_local());

        loop {
            futures::select! {
                // WebsocketConnection::onMessage(ByteString)
                frame = self.stream.next() => match frame {
                    Some(WebSocketStreamItem::Message(frame)) => {
                        let env = self.process_frame(frame).await.transpose();
                        if let Some(env) = env {
                            sink.send(env).await?;
                        }
                    },
                    Some(WebSocketStreamItem::KeepAliveRequest) => {
                        let request = self.send_keep_alive().await;
                        match request {
                            Ok(request) => {
                                let request = request.map(|response| {
                                    if let Err(e) = response {
                                        log::warn!("Error from keep alive: {:?}", e);
                                    }
                                });
                                background_work.push(request.boxed_local());
                            },
                            Err(e) => log::warn!("Could not send keep alive: {}", e),
                        }
                    },
                    None => {
                        log::debug!("WebSocket stream ended.");
                        break;
                    },
                },
                _ = background_work.next() => {
                    // no op
                },
                complete => {
                    log::info!("select! complete");
                }
            }
        }

        Ok(())
    }

    async fn send_keep_alive(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), ServiceError>>, ServiceError>
    {
        let request = WebSocketRequestMessage {
            id: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            ),
            path: Some("/v1/keepalive".into()),
            verb: Some("GET".into()),
            ..Default::default()
        };
        let request = self.send_request(request).await?;
        Ok(async move {
            let response = request.await?;
            if response.status() == 200 {
                Ok(())
            } else {
                log::warn!(
                    "Response code for keep-alive is not 200: {:?}",
                    response
                );
                Err(ServiceError::UnhandledResponseCode {
                    http_code: response.status() as u16,
                })
            }
        })
    }

    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<Option<Envelope>, ServiceError> {
        let msg = WebSocketMessage::decode(frame)?;
        log::trace!("Decoded {:?}", msg);

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrameError {
                reason: "Unknown frame type".into(),
            }),
            (Type::Request, Some(request), _) => {
                // Java: MessagePipe::read
                let response = WebSocketResponseMessage::from_request(&request);

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
                        self.credentials.signaling_key.as_ref().expect(
                            "signaling_key required to decrypt envelopes",
                        ),
                        request.is_signal_key_encrypted(),
                    )?)
                } else {
                    None
                };

                if let Err(e) = self.send_response(response).await {
                    log::error!("Could not send response: {}", e);
                }

                Ok(result)
            },
            (Type::Request, None, _) => Err(ServiceError::InvalidFrameError {
                reason: "Type was request, but does not contain request."
                    .into(),
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) = self.requests.remove(&id) {
                        if let Err(e) = responder.send(response) {
                            log::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else {
                        log::warn!(
                            "Response for non existing request: {:?}",
                            response
                        );
                    }
                }

                Ok(None)
            },
            (Type::Response, _, None) => Err(ServiceError::InvalidFrameError {
                reason: "Type was response, but does not contain response."
                    .into(),
            }),
        }
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
