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
use serde::{Deserialize, Serialize};

use crate::messagepipe::{WebSocketService, WebSocketStreamItem};
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::{MismatchedDevices, ServiceError};

mod attachment_service;
mod sender;

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
/// This structure can be freely cloned, since this acts as a *facade* for multiple entry and exit
/// points.
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
    /// Whether to enable keep-alive or not (and send a request to this path)
    keep_alive_path: String,

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
        tracing::trace!("decoded {:?}", msg);

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrameError {
                reason: "Unknown frame type".into(),
            }),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                tracing::trace!("sending request with body");
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
                            tracing::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else if let Some(_x) =
                        self.outgoing_keep_alive_set.take(&id)
                    {
                        if response.status() != 200 {
                            tracing::warn!(
                                "Response code for keep-alive is not 200: {:?}",
                                response
                            );
                            return Err(ServiceError::UnhandledResponseCode {
                                http_code: response.status() as u16,
                            });
                        }
                    } else {
                        tracing::warn!(
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

    fn next_request_id(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        loop {
            let id = rng.gen();
            if !self.outgoing_request_map.contains_key(&id) {
                return id;
            }
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
                                request
                                    .id
                                    .filter(|x| !self.outgoing_request_map.contains_key(x))
                                    .unwrap_or_else(|| self.next_request_id()),
                            );
                            tracing::trace!("sending request {:?}", request);

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
                            tracing::debug!("Sending keep alive upon request");
                            let request = WebSocketRequestMessage {
                                id: Some(self.next_request_id()),
                                path: Some(self.keep_alive_path.clone()),
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
                            self.ws.send_message(buffer.into()).await?;
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
                            tracing::trace!("sending response {:?}", response);

                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Response.into()),
                                response: Some(response),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send_message(buffer.into()).await?;
                        }
                        Some(Err(e)) => {
                            tracing::error!("could not generate response to a Signal request; responder was canceled: {}. Continuing.", e);
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
        keep_alive_path: String,
    ) -> (Self, impl Future<Output = ()>) {
        // Create process
        let (incoming_request_sink, incoming_request_stream) = mpsc::channel(1);
        let (outgoing_request_sink, outgoing_requests) = mpsc::channel(1);

        let process = SignalWebSocketProcess {
            keep_alive_path,
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
                tracing::error!("SignalWebSocket: {}", e);
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

    pub(crate) async fn request_json<T>(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: serde::Deserialize<'de>,
    {
        let response = self.request(r).await?;
        if response.status() != 200 {
            tracing::debug!(
                "request_json with non-200 status code. message: {}",
                response.message()
            );
        }

        fn json<U>(body: &[u8]) -> Result<U, ServiceError>
        where
            for<'de> U: serde::Deserialize<'de>,
        {
            serde_json::from_slice(body).map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })
        }

        match response.status() {
            200 | 204 => json(response.body()),
            401 | 403 => Err(ServiceError::Unauthorized),
            404 => Err(ServiceError::NotFoundError),
            413 /* PAYLOAD_TOO_LARGE */ => Err(ServiceError::RateLimitExceeded) ,
            409 /* CONFLICT */ => {
                let mismatched_devices: MismatchedDevices =
                    json(response.body()).map_err(|e| {
                        tracing::error!(
                            "Failed to decode HTTP 409 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: 409,
                        }
                    })?;
                Err(ServiceError::MismatchedDevicesException(
                    mismatched_devices,
                ))
            },
            410 /* GONE */ => {
                let stale_devices =
                    json(response.body()).map_err(|e| {
                        tracing::error!(
                            "Failed to decode HTTP 410 response: {}",
                            e
                        );
                        ServiceError::UnhandledResponseCode {
                            http_code: 410,
                        }
                    })?;
                Err(ServiceError::StaleDevices(stale_devices))
            },
            428 /* PRECONDITION_REQUIRED */ => {
                let proof_required = json(response.body()).map_err(|e| {
                    tracing::error!("Failed to decode HTTP 428 response: {}", e);
                    ServiceError::UnhandledResponseCode {
                        http_code: 428,
                    }
                })?;
                Err(ServiceError::ProofRequiredError(proof_required))
            },
            _ => Err(ServiceError::UnhandledResponseCode {
                http_code: response.status() as u16,
            }),
        }
    }

    pub(crate) async fn get_json<T>(
        &mut self,
        path: &str,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        let request = WebSocketRequestMessage {
            path: Some(path.into()),
            verb: Some("GET".into()),
            ..Default::default()
        };
        self.request_json(request).await
    }

    pub(crate) async fn put_json<D, S>(
        &mut self,
        path: &str,
        value: S,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize,
    {
        self.put_json_with_headers(path, value, vec![]).await
    }

    pub(crate) async fn put_json_with_headers<'h, D, S>(
        &mut self,
        path: &str,
        value: S,
        mut extra_headers: Vec<String>,
    ) -> Result<D, ServiceError>
    where
        for<'de> D: Deserialize<'de>,
        S: Serialize,
    {
        extra_headers.push("content-type:application/json".into());
        let request = WebSocketRequestMessage {
            path: Some(path.into()),
            verb: Some("PUT".into()),
            headers: extra_headers,
            body: Some(serde_json::to_vec(&value).map_err(|e| {
                ServiceError::SendError {
                    reason: format!("Serializing JSON {}", e),
                }
            })?),
            ..Default::default()
        };
        self.request_json(request).await
    }
}
