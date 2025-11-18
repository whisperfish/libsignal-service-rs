use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard};

use std::future::Future;

use bytes::Bytes;
use futures::channel::oneshot::Canceled;
use futures::channel::{mpsc, oneshot};
use futures::future::BoxFuture;
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use reqwest::Method;
use reqwest_websocket::WebSocket;
use tokio::time::Instant;
use tracing::debug;

use crate::prelude::PushService;
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::{self, ServiceError, SignalServiceResponse};

pub mod account;
pub mod keys;
pub mod linking;
pub mod profile;
pub mod registration;
mod request;
mod sender;
pub mod stickers;

pub use request::WebSocketRequestMessageBuilder;

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

#[derive(Debug, Clone)]
pub struct Identified;

#[derive(Debug, Clone)]
pub struct Unidentified;

pub trait WebSocketType: 'static {}

impl WebSocketType for Identified {}

impl WebSocketType for Unidentified {}

/// A dispatching web socket client for the Signal web socket API.
///
/// This structure can be freely cloned, since this acts as a *facade* for multiple entry and exit
/// points.
#[derive(Clone)]
pub struct SignalWebSocket<C: WebSocketType> {
    _type: PhantomData<C>,
    // XXX: at the end of the migration, this should be CDN operations only
    pub(crate) unidentified_push_service: PushService,
    inner: Arc<Mutex<SignalWebSocketInner>>,
    request_sink: mpsc::Sender<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
}

struct SignalWebSocketInner {
    stream: Option<SignalRequestStream>,
}

struct SignalWebSocketProcess {
    /// Whether to enable keep-alive or not (and send a request to this path)
    keep_alive_path: String,

    /// Receives requests from the application, which we forward to Signal.
    requests: mpsc::Receiver<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
    /// Signal's requests should go in here, to be delivered to the application.
    request_sink: mpsc::Sender<RequestStreamItem>,

    outgoing_requests: HashMap<
        u64,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    >,

    outgoing_keep_alive_set: HashSet<u64>,

    outgoing_responses: FuturesUnordered<
        BoxFuture<'static, Result<WebSocketResponseMessage, Canceled>>,
    >,

    ws: WebSocket,
}

impl SignalWebSocketProcess {
    async fn process_frame(
        &mut self,
        frame: Vec<u8>,
    ) -> Result<(), ServiceError> {
        use prost::Message;
        let msg = WebSocketMessage::decode(Bytes::from(frame))?;
        if let Some(request) = &msg.request {
            tracing::trace!(
                msg_type =? msg.r#type(),
                request.id,
                request.verb,
                request.path,
                request_body_size_bytes = request.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?request.headers,
                "decoded WebSocketMessage request"
            );
        } else if let Some(response) = &msg.response {
            tracing::trace!(
                msg_type =? msg.r#type(),
                response.status,
                response.message,
                response_body_size_bytes = response.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?response.headers,
                response.id,
                "decoded WebSocketMessage response"
            );
        } else {
            tracing::debug!("decoded {msg:?}");
        }

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrame {
                reason: "unknown frame type",
            }),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                tracing::trace!("sending request with body");
                self.request_sink.send((request, sink)).await.map_err(
                    |_| ServiceError::WsClosing {
                        reason: "request handler failed",
                    },
                )?;
                self.outgoing_responses.push(Box::pin(recv));

                Ok(())
            },
            (Type::Request, None, _) => Err(ServiceError::InvalidFrame {
                reason: "type was request, but does not contain request",
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) = self.outgoing_requests.remove(&id)
                    {
                        if let Err(e) = responder.send(Ok(response)) {
                            tracing::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else if let Some(_x) =
                        self.outgoing_keep_alive_set.take(&id)
                    {
                        let status_code = response.status();
                        if status_code != 200 {
                            tracing::warn!(
                                status_code,
                                "response code for keep-alive != 200"
                            );
                            return Err(ServiceError::UnhandledResponseCode {
                                http_code: response.status() as u16,
                            });
                        }
                    } else {
                        tracing::warn!(
                            ?response,
                            "response for non existing request"
                        );
                    }
                }

                Ok(())
            },
            (Type::Response, _, None) => Err(ServiceError::InvalidFrame {
                reason: "type was response, but does not contain response",
            }),
        }
    }

    fn next_request_id(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::rng();
        loop {
            let id = rng.random();
            if !self.outgoing_requests.contains_key(&id) {
                return id;
            }
        }
    }

    async fn run(mut self) -> Result<(), ServiceError> {
        let mut ka_interval = tokio::time::interval_at(
            Instant::now(),
            push_service::KEEPALIVE_TIMEOUT_SECONDS,
        );

        loop {
            futures::select! {
                _ = ka_interval.tick().fuse() => {
                    use prost::Message;
                    if !self.outgoing_keep_alive_set.is_empty() {
                        tracing::warn!("Websocket will be closed due to failed keepalives.");
                        if let Err(e) = self.ws.close(reqwest_websocket::CloseCode::Away, None).await {
                            tracing::debug!("Could not close WebSocket: {:?}", e);
                        }
                        self.outgoing_keep_alive_set.clear();
                        break;
                    }
                    tracing::debug!("sending keep-alive");
                    let request = WebSocketRequestMessage::new(Method::GET)
                        .id(self.next_request_id())
                        .path(&self.keep_alive_path)
                        .build();
                    self.outgoing_keep_alive_set.insert(request.id.unwrap());
                    let msg = WebSocketMessage {
                        r#type: Some(web_socket_message::Type::Request.into()),
                        request: Some(request),
                        ..Default::default()
                    };
                    let buffer = msg.encode_to_vec();
                    if let Err(e) = self.ws.send(reqwest_websocket::Message::Binary(buffer)).await {
                        tracing::info!("Websocket sink has closed: {:?}.", e);
                        break;
                    };
                },
                // Process requests from the application, forward them to Signal
                x = self.requests.next() => {
                    match x {
                        Some((mut request, responder)) => {
                            use prost::Message;

                            // Regenerate ID if already in the table
                            request.id = Some(
                                request
                                    .id
                                    .filter(|x| !self.outgoing_requests.contains_key(x))
                                    .unwrap_or_else(|| self.next_request_id()),
                            );
                            tracing::trace!(
                                request.id,
                                request.verb,
                                request.path,
                                request_body_size_bytes = request.body.as_ref().map(|x| x.len()),
                                ?request.headers,
                                "sending WebSocketRequestMessage",
                            );

                            self.outgoing_requests.insert(request.id.unwrap(), responder);
                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Request.into()),
                                request: Some(request),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(reqwest_websocket::Message::Binary(buffer)).await?
                        }
                        None => {
                            debug!("end of application request stream; websocket closing");
                            return Ok(());
                        }
                    }
                }
                // Incoming websocket message
                web_socket_item = self.ws.next().fuse() => {
                    use reqwest_websocket::Message;
                    match web_socket_item {
                        Some(Ok(Message::Close { code, reason })) => {
                            tracing::warn!(%code, reason, "websocket closed");
                            break;
                        },
                        Some(Ok(Message::Binary(frame))) => {
                            self.process_frame(frame).await?;
                        }
                        Some(Ok(Message::Ping(_))) => {
                            tracing::trace!("received ping");
                        }
                        Some(Ok(Message::Pong(_))) => {
                            tracing::trace!("received pong");
                        }
                        Some(Ok(Message::Text(_))) => {
                            tracing::trace!("received text (unsupported, skipping)");
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => {
                            return Err(ServiceError::WsClosing {
                                reason: "end of web request stream; socket closing"
                            });
                        }
                    }
                }
                response = self.outgoing_responses.next() => {
                    use prost::Message;
                    match response {
                        Some(Ok(response)) => {
                            tracing::trace!("sending response {:?}", response);

                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Response.into()),
                                response: Some(response),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(buffer.into()).await?;
                        }
                        Some(Err(error)) => {
                            tracing::error!(%error, "could not generate response to a Signal request; responder was canceled. continuing.");
                        }
                        None => {
                            unreachable!("outgoing responses should never fuse")
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<C: WebSocketType> SignalWebSocket<C> {
    fn inner_locked(&self) -> MutexGuard<'_, SignalWebSocketInner> {
        self.inner.lock().unwrap()
    }

    pub fn new(
        ws: WebSocket,
        keep_alive_path: String,
        unidentified_push_service: PushService,
    ) -> (Self, impl Future<Output = ()>) {
        // Create process
        let (incoming_request_sink, incoming_request_stream) = mpsc::channel(1);
        let (outgoing_request_sink, outgoing_requests) = mpsc::channel(1);

        let process = SignalWebSocketProcess {
            keep_alive_path,
            requests: outgoing_requests,
            request_sink: incoming_request_sink,
            outgoing_requests: HashMap::default(),
            outgoing_keep_alive_set: HashSet::new(),
            // Initializing the FuturesUnordered with a `pending` future means it will never fuse
            // itself, so an "empty" FuturesUnordered will still allow new futures to be added.
            outgoing_responses: vec![
                Box::pin(futures::future::pending()) as BoxFuture<_>
            ]
            .into_iter()
            .collect(),
            ws,
        };
        let process = process.run().map(|x| match x {
            Ok(()) => (),
            Err(e) => {
                tracing::error!("SignalWebSocket: {}", e);
            },
        });

        (
            Self {
                _type: PhantomData,
                request_sink: outgoing_request_sink,
                unidentified_push_service,
                inner: Arc::new(Mutex::new(SignalWebSocketInner {
                    stream: Some(SignalRequestStream {
                        inner: incoming_request_stream,
                    }),
                })),
            },
            process,
        )
    }

    pub fn is_closed(&self) -> bool {
        self.request_sink.is_closed()
    }

    pub fn is_used(&self) -> bool {
        self.inner_locked().stream.is_none()
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
                    reason: "WebSocket closing while sending request",
                });
            }
            // Handle the oneshot sender error for dropped senders.
            match recv.await {
                Ok(x) => x,
                Err(_) => Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while waiting for a response",
                }),
            }
        }
    }

    pub(crate) async fn request_json<T>(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: serde::Deserialize<'de>,
    {
        self.request(r)
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }
}

impl WebSocketResponseMessage {
    pub async fn service_error_for_status(self) -> Result<Self, ServiceError> {
        super::push_service::response::service_error_for_status(self).await
    }

    pub async fn json<T: for<'a> serde::Deserialize<'a>>(
        &self,
    ) -> Result<T, ServiceError> {
        self.body
            .as_ref()
            .ok_or(ServiceError::UnsupportedContent)
            .and_then(|b| serde_json::from_slice(b).map_err(Into::into))
    }
}
