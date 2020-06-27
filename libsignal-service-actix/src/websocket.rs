use actix::prelude::*;
use awc::{error::WsProtocolError, ws};
use futures::{channel::mpsc::*, prelude::*};
use url::Url;

use libsignal_service::push_service::ServiceError;

pub struct AwcWebSocket {
    actor: Addr<AwcWebSocketActor>,
    messagestream: Receiver<()>,
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

impl AwcWebSocket {
    pub(crate) async fn with_client(
        client: &mut awc::Client,
        base_url: impl std::borrow::Borrow<Url>,
    ) -> Result<Self, AwcWebSocketError> {
        let url = base_url.borrow().join("/v1/websocket").expect("valid url");
        let (_response, framed) = client.ws(url.as_str()).connect().await?;

        log::debug!("WebSocket connected: {:?}", _response);

        let (sink, stream) = framed.split();

        let (messagesink, messagestream) = channel(1);
        let actor = AwcWebSocketActor::create(move |ctx| {
            ctx.add_stream(stream);

            AwcWebSocketActor {
                sink: Box::new(sink),
                messagesink,
            }
        });

        Ok(Self {
            actor,
            messagestream,
        })
    }
}

struct AwcWebSocketActor {
    // XXX: in principle, this type is completely known...
    sink: Box<dyn Sink<ws::Message, Error = WsProtocolError>>,
    messagesink: Sender<()>,
}

impl Actor for AwcWebSocketActor {
    type Context = Context<Self>;
}

impl StreamHandler<Result<ws::Frame, WsProtocolError>> for AwcWebSocketActor {
    fn handle(
        &mut self,
        _: Result<ws::Frame, WsProtocolError>,
        _ctx: &mut Self::Context,
    ) {
        log::trace!("Message on the WS");
    }
}
