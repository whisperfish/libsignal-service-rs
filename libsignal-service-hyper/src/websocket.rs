use std::sync::Arc;

use async_tungstenite::{
    tokio::connect_async_with_tls_connector,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderName, StatusCode},
        Error as TungsteniteError, Message,
    },
};
use bytes::Bytes;
use futures::{channel::mpsc::*, prelude::*};
use tokio::time::Instant;
use tokio_rustls::rustls;
use url::Url;

use libsignal_service::{
    configuration::ServiceCredentials,
    messagepipe::*,
    push_service::{self, ServiceError},
    MaybeSend,
};

// This weird one-time trait is required because MaybeSend, unlike Send, is not
// an auto trait. Only auto traits can be used as additional traits in a trait object.
trait MaybeSendSink: Sink<Message, Error = TungsteniteError> + MaybeSend {}
impl<T> MaybeSendSink for T where
    T: Sink<Message, Error = TungsteniteError> + MaybeSend
{
}

pub struct TungsteniteWebSocket {
    socket_sink: Box<dyn MaybeSendSink + Unpin>,
}

#[derive(thiserror::Error, Debug)]
pub enum TungsteniteWebSocketError {
    #[error("error while connecting to websocket: {0}")]
    ConnectionError(#[from] TungsteniteError),
}

impl From<TungsteniteWebSocketError> for ServiceError {
    fn from(e: TungsteniteWebSocketError) -> Self {
        match e {
            TungsteniteWebSocketError::ConnectionError(
                TungsteniteError::Http(response),
            ) => match response.status() {
                StatusCode::FORBIDDEN => ServiceError::Unauthorized,
                s => ServiceError::WsError {
                    reason: format!("HTTP status {}", s),
                },
            },
            e => ServiceError::WsError {
                reason: e.to_string(),
            },
        }
    }
}

// impl From<AwcWebSocketError> for ServiceError {
//     fn from(e: AwcWebSocketError) -> ServiceError {
//         match e {
//             AwcWebSocketError::ConnectionError(e) => match e {
//                 WsClientError::InvalidResponseStatus(s) => match s {
//                     StatusCode::FORBIDDEN => ServiceError::Unauthorized,
//                     s => ServiceError::WsError {
//                         reason: format!("HTTP status {}", s),
//                     },
//                 },
//                 e => ServiceError::WsError {
//                     reason: e.to_string(),
//                 },
//             },
//         }
//     }
// }

// impl From<WsProtocolError> for AwcWebSocketError {
//     fn from(e: WsProtocolError) -> AwcWebSocketError {
//         todo!("error conversion {:?}", e)
//         // return Some(Err(ServiceError::WsError {
//         //     reason: e.to_string(),
//         // }));
//     }
// }

// Process the WebSocket, until it times out.
async fn process<S>(
    socket_stream: S,
    mut incoming_sink: Sender<WebSocketStreamItem>,
) -> Result<(), TungsteniteWebSocketError>
where
    S: Stream<Item = Result<Message, TungsteniteError>> + Unpin,
{
    let mut socket_stream = socket_stream.fuse();

    let mut ka_interval = tokio::time::interval_at(
        Instant::now(),
        push_service::KEEPALIVE_TIMEOUT_SECONDS,
    );

    loop {
        tokio::select! {
            _ = ka_interval.tick() => {
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
                    Message::Binary(s) => s,
                    Message::Ping(msg) => {
                        tracing::warn!("Received Ping({:?})", msg);

                        continue;
                    },
                    Message::Pong(msg) => {
                        tracing::trace!("Received Pong({:?})", msg);

                        continue;
                    },
                    Message::Text(frame) => {
                        tracing::warn!("Message::Text {:?}", frame);

                        // this is a protocol violation, maybe break; is better?
                        continue;
                    },

                    Message::Close(c) => {
                        tracing::warn!("Websocket closing: {:?}", c);

                        break;
                    },
                    Message::Frame(_f) => unreachable!("handled internally in Tungstenite")
                };

                // Match SendError
                if let Err(e) = incoming_sink.send(WebSocketStreamItem::Message(Bytes::from(frame))).await {
                    tracing::info!("Websocket sink has closed: {:?}.", e);
                    break;
                }
            },
        }
    }
    Ok(())
}

impl TungsteniteWebSocket {
    pub(crate) async fn with_tls_config(
        tls_config: rustls::ClientConfig,
        base_url: impl std::borrow::Borrow<Url>,
        path: &str,
        additional_headers: &[(&str, &str)],
        credentials: Option<&ServiceCredentials>,
    ) -> Result<
        (Self, <Self as WebSocketService>::Stream),
        TungsteniteWebSocketError,
    > {
        let mut url = base_url.borrow().join(path).expect("valid url");
        url.set_scheme("wss").expect("valid https base url");

        let tls_connector =
            tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        if let Some(credentials) = credentials {
            url.query_pairs_mut()
                .append_pair("login", &credentials.login())
                .append_pair(
                    "password",
                    credentials.password.as_ref().expect("a password"),
                );
        }

        tracing::trace!("Will start websocket at {:?}", url);

        let mut request = url.into_client_request()?;

        for (key, value) in additional_headers {
            request.headers_mut().insert(
                // FromStr is implemnted for HeaderName, but that expects a &'static str...
                HeaderName::from_bytes(key.as_bytes())
                    .expect("valid header name"),
                value.parse().expect("valid header value"),
            );
        }

        let (socket_stream, response) =
            connect_async_with_tls_connector(request, Some(tls_connector))
                .await?;

        tracing::debug!("WebSocket connected: {:?}", response);

        let (incoming_sink, incoming_stream) = channel(5);

        let (socket_sink, socket_stream) = socket_stream.split();
        let processing_task = process(socket_stream, incoming_sink);

        // When the processing_task stops, the consuming stream and sink also
        // terminate.
        tokio::spawn(processing_task.map(|v| match v {
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

#[cfg_attr(feature = "unsend-futures", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "unsend-futures"), async_trait::async_trait)]
impl WebSocketService for TungsteniteWebSocket {
    type Stream = Receiver<WebSocketStreamItem>;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError> {
        self.socket_sink
            .send(Message::Binary(msg.to_vec()))
            .await
            .map_err(TungsteniteWebSocketError::from)?;
        Ok(())
    }
}
