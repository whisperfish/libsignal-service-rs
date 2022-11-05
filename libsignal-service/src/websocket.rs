use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use std::future::Future;

use bytes::Bytes;
use futures::channel::oneshot::Canceled;
use futures::channel::{mpsc, oneshot};
use futures::future::BoxFuture;
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use prost::Message;

use crate::messagepipe::{WebSocketService, WebSocketStreamItem};
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::ServiceError;

type RequestStreamItem = (
    WebSocketRequestMessage,
    oneshot::Sender<WebSocketResponseMessage>,
);

pub struct SignalRequestStream {
    inner: mpsc::Receiver<RequestStreamItem>,
}

impl Stream for SignalRequestStream {
    type Item = RequestStreamItem;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let inner = &mut self.inner;
        futures::pin_mut!(inner);
        Stream::poll_next(inner, cx)
    }
}

/// A dispatching web socket client for the Signal web socket API.
///
/// This structure can be freely cloned.
#[derive(Clone)]
pub struct SignalWebSocket {
    inner: Arc<Mutex<SignalWebSocketInner>>,
    request_sink: mpsc::Sender<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
}

struct SignalWebSocketInner {
    stream: Option<SignalRequestStream>,
}

struct SignalWebSocketProcess<WS: WebSocketService> {
    /// Receives requests from the application, which we forward to Signal.
    requests: mpsc::Receiver<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
    /// Signal's requests should go in here, to be delivered to the application.
    request_sink: mpsc::Sender<RequestStreamItem>,

    outgoing_request_map: HashMap<
        u64,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    >,

    outgoing_keep_alive_set: HashSet<u64>,

    outgoing_responses: FuturesUnordered<
        BoxFuture<'static, Result<WebSocketResponseMessage, Canceled>>,
    >,

    // WS backend stuff
    ws: WS,
    stream: WS::Stream,
}

impl<WS: WebSocketService> SignalWebSocketProcess<WS> {
    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<(), ServiceError> {
        let msg = WebSocketMessage::decode(frame)?;
        log::trace!("Decoded {:?}", msg);

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrameError {
                reason: "Unknown frame type".into(),
            }),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                self.request_sink.send((request, sink)).await.map_err(
                    |_| ServiceError::WsError {
                        reason: "request handler failed".into(),
                    },
                )?;
                self.outgoing_responses.push(Box::pin(recv));

                Ok(())
            },
            (Type::Request, None, _) => Err(ServiceError::InvalidFrameError {
                reason: "Type was request, but does not contain request."
                    .into(),
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) =
                        self.outgoing_request_map.remove(&id)
                    {
                        if let Err(e) = responder.send(Ok(response)) {
                            log::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else if let Some(_x) =
                        self.outgoing_keep_alive_set.take(&id)
                    {
                        if response.status() != 200 {
                            log::warn!(
                                "Response code for keep-alive is not 200: {:?}",
                                response
                            );
                            return Err(ServiceError::UnhandledResponseCode {
                                http_code: response.status() as u16,
                            });
                        }
                    } else {
                        log::warn!(
                            "Response for non existing request: {:?}",
                            response
                        );
                    }
                }

                Ok(())
            },
            (Type::Response, _, None) => Err(ServiceError::InvalidFrameError {
                reason: "Type was response, but does not contain response."
                    .into(),
            }),
        }
    }

    async fn run(mut self) -> Result<(), ServiceError> {
        loop {
            futures::select! {
                // Process requests from the application, forward them to Signal
                x = self.requests.next() => {
                    match x {
                        Some((mut request, responder)) => {
                            // Regenerate ID if already in the table
                            request.id = Some(
                                request.id.filter(|x| self.outgoing_request_map.contains_key(x)).unwrap_or(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis() as u64,
                                ),
                            );
                            log::trace!("Sending request {:?}", request);

                            self.outgoing_request_map.insert(request.id.unwrap(), responder);
                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Request.into()),
                                request: Some(request),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send_message(buffer.into()).await?
                        }
                        None => {
                            return Err(ServiceError::WsError {
                                reason: "SignalWebSocket: end of application request stream; socket closing".into()
                            });
                        }
                    }
                }
                web_socket_item = self.stream.next() => {
                    match web_socket_item {
                        Some(WebSocketStreamItem::Message(frame)) => {
                            self.process_frame(frame).await?;
                        }
                        Some(WebSocketStreamItem::KeepAliveRequest) => {
                            // XXX: would be nicer if we could drop this request into the request
                            // queue above.
                            log::debug!("Sending keep alive upon request");
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
                            self.outgoing_keep_alive_set.insert(request.id.unwrap());
                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Request.into()),
                                request: Some(request),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send_message(buffer.into()).await?
                        }
                        None => {
                            return Err(ServiceError::WsError {
                                reason: "end of web request stream; socket closing".into()
                            });
                        }
                    }
                }
                response = self.outgoing_responses.next() => {
                    match response {
                        Some(Ok(response)) => {
                            log::trace!("Sending response {:?}", response);

                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Response.into()),
                                response: Some(response),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send_message(buffer.into()).await?;
                        }
                        Some(Err(e)) => {
                            log::error!("could not generate response to a Signal request; responder was canceled: {}. Continuing.", e);
                        }
                        None => {
                            unreachable!("outgoing responses should never fuse")
                        }
                    }
                }
            }
        }
    }
}

impl SignalWebSocket {
    fn inner_locked(&self) -> MutexGuard<'_, SignalWebSocketInner> {
        self.inner.lock().unwrap()
    }

    pub fn from_socket<WS: WebSocketService + 'static>(
        ws: WS,
        stream: WS::Stream,
    ) -> (Self, std::pin::Pin<Box<dyn Future<Output = ()>>>) {
        // Create process
        let (incoming_request_sink, incoming_request_stream) = mpsc::channel(1);
        let (outgoing_request_sink, outgoing_requests) = mpsc::channel(1);

        let process = SignalWebSocketProcess {
            requests: outgoing_requests,
            request_sink: incoming_request_sink,
            outgoing_request_map: HashMap::default(),
            outgoing_keep_alive_set: HashSet::new(),
            // Initializing the FuturesUnordered with a `pending` future means it will never fuse
            // itself, so an "empty" FuturesUnordered will still allow new futures to be added.
            outgoing_responses: vec![
                Box::pin(futures::future::pending()) as BoxFuture<_>
            ]
            .into_iter()
            .collect(),
            ws,
            stream,
        };
        let process = process.run().map(|x| match x {
            Ok(()) => (),
            Err(e) => {
                log::error!("SignalWebSocket: {}", e);
            },
        });

        (
            Self {
                request_sink: outgoing_request_sink,
                inner: Arc::new(Mutex::new(SignalWebSocketInner {
                    stream: Some(SignalRequestStream {
                        inner: incoming_request_stream,
                    }),
                })),
            },
            Box::pin(process),
        )
    }

    pub(crate) fn take_request_stream(
        &mut self,
    ) -> Option<SignalRequestStream> {
        self.inner_locked().stream.take()
    }

    pub(crate) fn return_request_stream(&mut self, r: SignalRequestStream) {
        self.inner_locked().stream.replace(r);
    }

    // XXX Ideally, this should take an *async* closure, then we could get rid of the
    // `take_request_stream` and `return_request_stream`.
    pub async fn with_request_stream<
        R: 'static,
        F: FnOnce(&mut SignalRequestStream) -> R,
    >(
        &mut self,
        f: F,
    ) -> R {
        let mut s = self
            .inner_locked()
            .stream
            .take()
            .expect("request stream invariant");
        let r = f(&mut s);
        self.inner_locked().stream.replace(s);
        r
    }

    pub fn request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>
    {
        let (sink, recv): (
            oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
            _,
        ) = oneshot::channel();

        let mut request_sink = self.request_sink.clone();
        async move {
            if let Err(_e) = request_sink.send((r, sink)).await {
                return Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while sending request.".into(),
                });
            }
            // Handle the oneshot sender error for dropped senders.
            match recv.await {
                Ok(x) => x,
                Err(_) => Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while waiting for a response."
                        .into(),
                }),
            }
        }
    }
}
