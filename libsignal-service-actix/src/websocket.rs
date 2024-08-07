use awc::{
    error::{WsClientError, WsProtocolError},
    http::StatusCode,
    ws,
    ws::Frame,
};
use bytes::Bytes;
use futures::{channel::mpsc::*, prelude::*};
use url::Url;

use libsignal_service::{
    configuration::ServiceCredentials,
    messagepipe::*,
    push_service::{self, ServiceError},
};

pub struct AwcWebSocket {
    socket_sink: Box<dyn Sink<ws::Message, Error = WsProtocolError> + Unpin>,
}

#[derive(thiserror::Error, Debug)]
pub enum AwcWebSocketError {
    #[error("Could not connect to the Signal Server")]
    ConnectionError(#[from] awc::error::WsClientError),
    #[error("Error during Websocket connection")]
    ProtocolError(#[from] WsProtocolError),
}

impl From<AwcWebSocketError> for ServiceError {
    fn from(e: AwcWebSocketError) -> ServiceError {
        match e {
            AwcWebSocketError::ConnectionError(e) => match e {
                WsClientError::InvalidResponseStatus(s) => match s {
                    StatusCode::FORBIDDEN => ServiceError::Unauthorized,
                    s => ServiceError::WsError {
                        reason: format!("HTTP status {}", s),
                    },
                },
                e => ServiceError::WsError {
                    reason: e.to_string(),
                },
            },
            AwcWebSocketError::ProtocolError(e) => match e {
                WsProtocolError::Io(e) => match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => {
                        ServiceError::WsClosing {
                            reason: format!(
                                "WebSocket closing due to unexpected EOF: {}",
                                e
                            ),
                        }
                    },
                    _ => ServiceError::WsError {
                        reason: format!(
                            "IO error during WebSocket connection: {}",
                            e
                        ),
                    },
                },
                e => ServiceError::WsError {
                    reason: e.to_string(),
                },
            },
        }
    }
}

/// Process the WebSocket, until it times out.
async fn process<S>(
    socket_stream: S,
    mut incoming_sink: Sender<WebSocketStreamItem>,
) -> Result<(), AwcWebSocketError>
where
    S: Unpin,
    S: Stream<Item = Result<Frame, WsProtocolError>>,
{
    let mut socket_stream = socket_stream.fuse();

    let mut ka_interval = actix::clock::interval_at(
        actix::clock::Instant::now(),
        push_service::KEEPALIVE_TIMEOUT_SECONDS,
    );

    loop {
        let tick = ka_interval.tick().fuse();
        futures::pin_mut!(tick);
        futures::select! {
            _ = tick => {
                tracing::trace!("Triggering keep-alive");
                if let Err(e) = incoming_sink.send(WebSocketStreamItem::KeepAliveRequest).await {
                    tracing::info!("Websocket sink has closed: {:?}.", e);
                    break;
                };
            },
            frame = socket_stream.next() => {
                let frame = if let Some(frame) = frame {
                    frame
                } else {
                    tracing::info!("process: Socket stream ended");
                    break;
                };

                let frame = match frame? {
                    Frame::Binary(s) => s,

                    Frame::Continuation(_c) => todo!(),
                    Frame::Ping(msg) => {
                        tracing::warn!(?msg, "received Ping");

                        continue;
                    },
                    Frame::Pong(msg) => {
                        tracing::trace!(?msg, "received Pong");

                        continue;
                    },
                    Frame::Text(frame) => {
                        tracing::warn!(?frame, "frame::Text",);

                        // this is a protocol violation, maybe break; is better?
                        continue;
                    },

                    Frame::Close(c) => {
                        tracing::warn!(?c, "Websocket closing");

                        break;
                    },
                };

                // Match SendError
                if let Err(e) = incoming_sink.send(WebSocketStreamItem::Message(frame)).await {
                    tracing::info!("Websocket sink has closed: {:?}.", e);
                    break;
                }
            },
        }
    }
    Ok(())
}

impl AwcWebSocket {
    pub(crate) async fn with_client(
        client: &mut awc::Client,
        base_url: impl std::borrow::Borrow<Url>,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials: Option<&ServiceCredentials>,
    ) -> Result<(Self, <Self as WebSocketService>::Stream), AwcWebSocketError>
    {
        let mut url = base_url.borrow().join(path).expect("valid url");
        url.set_scheme("wss").expect("valid https base url");

        if let Some(credentials) = credentials {
            url.query_pairs_mut()
                .append_pair("login", credentials.login().as_ref())
                .append_pair(
                    "password",
                    credentials.password.as_ref().expect("a password"),
                );
        }

        tracing::trace!(
            url.scheme = url.scheme(),
            url.host = ?url.host(),
            url.path = url.path(),
            url.has_query = ?url.query().is_some(),
            "starting websocket",
        );
        let mut ws = client.ws(url.as_str());
        for (key, value) in additional_headers {
            ws = ws.header(*key, *value);
        }
        let (response, framed) = ws.connect().await?;

        tracing::debug!(?response, "WebSocket connected");

        let (incoming_sink, incoming_stream) = channel(5);

        let (socket_sink, socket_stream) = framed.split();
        let processing_task = process(socket_stream, incoming_sink);

        // When the processing_task stops, the consuming stream and sink also
        // terminate.
        actix_rt::spawn(processing_task.map(|v| match v {
            Ok(()) => (),
            Err(e) => {
                tracing::warn!("Processing task terminated with error: {:?}", e)
            },
        }));

        Ok((
            Self {
                socket_sink: Box::new(socket_sink),
            },
            incoming_stream,
        ))
    }
}

#[async_trait::async_trait(?Send)]
impl WebSocketService for AwcWebSocket {
    type Stream = Receiver<WebSocketStreamItem>;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError> {
        self.socket_sink
            .send(ws::Message::Binary(msg))
            .await
            .map_err(AwcWebSocketError::from)?;
        Ok(())
    }
}
