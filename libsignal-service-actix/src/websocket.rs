use actix::Arbiter;

use awc::{error::WsProtocolError, ws, ws::Frame};
use bytes::Bytes;
use futures::{channel::mpsc::*, prelude::*};
use url::Url;

use libsignal_service::{
    configuration::Credentials, messagepipe::*, push_service::ServiceError,
};

pub struct AwcWebSocket {
    socket_sink: Box<dyn Sink<ws::Message, Error = WsProtocolError> + Unpin>,
}

#[derive(thiserror::Error, Debug)]
pub enum AwcWebSocketError {
    #[error("Could not connect to the Signal Server")]
    ConnectionError(#[from] awc::error::WsClientError),
}

impl From<AwcWebSocketError> for ServiceError {
    fn from(e: AwcWebSocketError) -> ServiceError {
        todo!("error conversion {:?}", e)
    }
}

impl From<WsProtocolError> for AwcWebSocketError {
    fn from(e: WsProtocolError) -> AwcWebSocketError {
        todo!("error conversion {:?}", e)
        // return Some(Err(ServiceError::WsError {
        //     reason: e.to_string(),
        // }));
    }
}

/// Process the WebSocket, until it times out.
async fn process<S: Stream>(
    mut socket_stream: S,
    mut incoming_sink: Sender<Bytes>,
) -> Result<(), AwcWebSocketError>
where
    S: Unpin,
    S: Stream<Item = Result<Frame, WsProtocolError>>,
{
    while let Some(frame) = socket_stream.next().await {
        let frame = match frame? {
            Frame::Binary(s) => s,

            Frame::Continuation(_c) => todo!(),
            Frame::Ping(msg) => {
                log::warn!("Received Ping({:?})", msg);
                // XXX: send pong and make the above log::debug
                continue;
            },
            Frame::Pong(msg) => {
                log::trace!("Received Pong({:?})", msg);

                continue;
            },
            Frame::Text(frame) => {
                log::warn!("Frame::Text {:?}", frame);

                // this is a protocol violation, maybe break; is better?
                continue;
            },

            Frame::Close(c) => {
                log::warn!("Websocket closing: {:?}", c);

                break;
            },
        };

        // Match SendError
        if let Err(e) = incoming_sink.send(frame).await {
            log::info!("Websocket sink has closed: {:?}.", e);
            break;
        }
    }
    Ok(())
}

impl AwcWebSocket {
    pub(crate) async fn with_client(
        client: &mut awc::Client,
        base_url: impl std::borrow::Borrow<Url>,
        credentials: Option<&Credentials>,
    ) -> Result<(Self, <Self as WebSocketService>::Stream), AwcWebSocketError>
    {
        let mut url =
            base_url.borrow().join("/v1/websocket/").expect("valid url");
        url.set_scheme("wss").expect("valid https base url");

        if let Some(credentials) = credentials {
            url.query_pairs_mut()
                .append_pair("login", credentials.login())
                .append_pair(
                    "password",
                    credentials.password.as_ref().expect("a password"),
                );
        }

        log::trace!("Will start websocket at {:?}", url);
        let (response, framed) = client.ws(url.as_str()).connect().await?;

        log::debug!("WebSocket connected: {:?}", response);

        let (incoming_sink, incoming_stream) = channel(1);

        let (socket_sink, socket_stream) = framed.split();
        let processing_task = process(socket_stream, incoming_sink);

        // When the processing_task stops, the consuming stream and sink also
        // terminate.
        Arbiter::spawn(processing_task.map(|v| match v {
            Ok(()) => (),
            Err(e) => {
                log::warn!("Processing task terminated with error: {:?}", e)
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
    type Stream = Receiver<Bytes>;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError> {
        self.socket_sink
            .send(ws::Message::Binary(msg))
            .await
            .map_err(AwcWebSocketError::from)?;
        Ok(())
    }
}
