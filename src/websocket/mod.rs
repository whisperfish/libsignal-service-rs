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

use crate::configuration::SignalServers;
use crate::prelude::PushService;
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::{self, ServiceError, SignalServiceResponse};

pub mod account;
#[cfg(feature = "cdsi")]
pub mod directory;
pub mod error;
pub mod keys;
pub mod linking;
pub mod profile;
pub mod registration;
mod request;
mod sender;
pub mod stickers;
mod usernames;

pub use error::{
    HandshakeError, InvalidFrame, WebSocketError, WebSocketOperation,
    WsClosingReason,
};
pub use request::WebSocketRequestMessageBuilder;
pub use usernames::UsernameLinkError;

type RequestStreamItem = (
    WebSocketRequestMessage,
    oneshot::Sender<WebSocketResponseMessage>,
);

pub struct SignalRequestStream {
    inner: mpsc::UnboundedReceiver<RequestStreamItem>,
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
    /// The task running the socket, when `PushService::ws` spawned it; taken by
    /// [`SignalWebSocket::outcome`].
    task: Option<tokio::task::JoinHandle<Result<(), ServiceError>>>,
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
    request_sink: mpsc::UnboundedSender<RequestStreamItem>,

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
        frame: Bytes,
    ) -> Result<(), ServiceError> {
        use prost::Message;
        let msg = WebSocketMessage::decode(frame)?;
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
            (Type::Unknown, _, _) => Err(InvalidFrame::UnknownType.into()),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                tracing::trace!("sending request with body");
                self.request_sink.send((request, sink)).await.map_err(
                    |_| ServiceError::WsClosing {
                        reason: WsClosingReason::RequestStreamDropped,
                    },
                )?;
                self.outgoing_responses.push(Box::pin(recv));

                Ok(())
            },
            (Type::Request, None, _) => {
                Err(InvalidFrame::RequestWithoutRequest.into())
            },
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
                        let status = u16::try_from(response.status())
                            .ok()
                            .and_then(|status| {
                                reqwest::StatusCode::from_u16(status).ok()
                            })
                            .ok_or(InvalidFrame::InvalidKeepAliveStatus(
                                response.status(),
                            ))?;
                        if !status.is_success() {
                            tracing::warn!(
                                %status,
                                "response code for keep-alive not successful"
                            );
                            return Err(ServiceError::UnhandledResponseCode {
                                status,
                                body: String::from_utf8_lossy(response.body())
                                    .into_owned(),
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
            (Type::Response, _, None) => {
                Err(InvalidFrame::ResponseWithoutResponse.into())
            },
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
        // A keepalive sent before the server registers our presence makes it close the socket.
        let mut ka_interval = tokio::time::interval_at(
            Instant::now() + push_service::KEEPALIVE_TIMEOUT_SECONDS,
            push_service::KEEPALIVE_TIMEOUT_SECONDS,
        );

        loop {
            futures::select! {
                _ = ka_interval.tick().fuse() => {
                    use prost::Message;
                    if !self.outgoing_keep_alive_set.is_empty() {
                        tracing::warn!("Websocket will be closed due to failed keepalives.");
                        if let Err(error) = self.ws.close(reqwest_websocket::CloseCode::Away, None).await {
                            let error = WebSocketError::new(WebSocketOperation::Close, error);
                            tracing::debug!(error = &error as &dyn std::error::Error, "couldn't close the websocket");
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
                    self.ws.send(reqwest_websocket::Message::Binary(buffer.into())).await.map_err(|error| {
                        WebSocketError::new(WebSocketOperation::SendKeepAlive, error)
                    })?;
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
                            self.ws.send(reqwest_websocket::Message::Binary(buffer.into())).await.map_err(|error| {
                                WebSocketError::new(WebSocketOperation::SendRequest, error)
                            })?;
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
                        Some(Err(error)) => {
                            return Err(WebSocketError::new(WebSocketOperation::Receive, error).into());
                        }
                        None => {
                            return Err(ServiceError::WsClosing {
                                reason: WsClosingReason::StreamEnded,
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
                            self.ws.send(buffer.into()).await.map_err(|error| {
                                WebSocketError::new(WebSocketOperation::SendResponse, error)
                            })?;
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

    /// Returns the socket's facade and the task that runs it. The task ends with why the
    /// socket closed, having logged it; `Ok` when the application let go of the socket.
    pub fn new(
        ws: WebSocket,
        keep_alive_path: String,
        unidentified_push_service: PushService,
    ) -> (Self, impl Future<Output = Result<(), ServiceError>>) {
        // Create process
        let (incoming_request_sink, incoming_request_stream) =
            mpsc::unbounded();
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
        // Logged as well as returned: the socket's users only see `WsClosing`, and whoever
        // holds the task may never ask.
        let process = process.run().inspect_err(|error| {
            tracing::error!(
                error = error as &dyn std::error::Error,
                "websocket task ended"
            );
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
                    task: None,
                })),
            },
            process,
        )
    }

    pub fn servers(&self) -> SignalServers {
        self.unidentified_push_service.servers
    }

    pub fn is_closed(&self) -> bool {
        self.request_sink.is_closed()
    }

    /// Keeps the handle of the spawned task, for [`Self::outcome`].
    pub(crate) fn set_task(
        &self,
        task: tokio::task::JoinHandle<Result<(), ServiceError>>,
    ) {
        self.inner_locked().task = Some(task);
    }

    /// Waits for the socket's task to end, and says why: `Ok` when the application let go
    /// of the socket, the error otherwise. The task is awaited once: later calls, and calls
    /// on a socket whose task wasn't spawned by `PushService::ws`, return `None`.
    pub async fn outcome(&self) -> Option<Result<(), ServiceError>> {
        let task = self.inner_locked().task.take()?;
        Some(task.await.unwrap_or_else(|panicked| {
            tracing::error!(
                error = &panicked as &dyn std::error::Error,
                "websocket task panicked"
            );
            Err(ServiceError::WsClosing {
                reason: WsClosingReason::TaskPanicked,
            })
        }))
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
                    reason: WsClosingReason::TaskEnded,
                });
            }
            // Handle the oneshot sender error for dropped senders.
            match recv.await {
                Ok(x) => x,
                Err(_) => Err(ServiceError::WsClosing {
                    reason: WsClosingReason::ResponsePending,
                }),
            }
        }
    }

    pub(crate) async fn request_json_with<T, F, Fut>(
        &mut self,
        r: WebSocketRequestMessage,
        decode: F,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: serde::Deserialize<'de>,
        F: FnOnce(WebSocketResponseMessage) -> Fut + Send,
        Fut: Future<Output = Result<WebSocketResponseMessage, ServiceError>>
            + Send,
    {
        self.request(r)
            .await?
            .service_error_for_status_with(decode)
            .await?
            .json()
            .await
    }
}

impl WebSocketResponseMessage {
    pub async fn json<T: for<'a> serde::Deserialize<'a>>(
        &self,
    ) -> Result<T, ServiceError> {
        self.body
            .as_ref()
            .ok_or(ServiceError::UnsupportedContent)
            .and_then(|b| serde_json::from_slice(b).map_err(Into::into))
    }
}
