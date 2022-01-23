use bytes::Bytes;
use futures::{
    channel::mpsc::{self, Sender},
    prelude::*,
    stream::FuturesUnordered,
};
use pin_project::pin_project;
use prost::Message;
use url::Url;

pub use crate::proto::{
    ProvisionEnvelope, ProvisionMessage, ProvisioningVersion,
};

use crate::{
    messagepipe::{WebSocketService, WebSocketStreamItem},
    proto::{
        web_socket_message, ProvisioningUuid, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
    provisioning::ProvisioningError,
};

use super::cipher::ProvisioningCipher;

#[pin_project]
pub struct ProvisioningPipe<WS: WebSocketService> {
    ws: WS,
    #[pin]
    stream: WS::Stream,
    provisioning_cipher: ProvisioningCipher,
}

#[derive(Debug)]
pub enum ProvisioningStep {
    Url(Url),
    Message(ProvisionMessage),
}

impl<WS: WebSocketService> ProvisioningPipe<WS> {
    pub fn from_socket(
        ws: WS,
        stream: WS::Stream,
    ) -> Result<Self, ProvisioningError> {
        Ok(ProvisioningPipe {
            ws,
            stream,
            provisioning_cipher: ProvisioningCipher::generate(
                &mut rand::thread_rng(),
            )?,
        })
    }

    async fn send_ok_response(
        &mut self,
        id: Option<u64>,
    ) -> Result<(), ProvisioningError> {
        self.send_response(WebSocketResponseMessage {
            id,
            status: Some(200),
            message: Some("OK".into()),
            body: None,
            headers: vec![],
        })
        .await
    }

    async fn send_response(
        &mut self,
        r: WebSocketResponseMessage,
    ) -> Result<(), ProvisioningError> {
        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response.into()),
            response: Some(r),
            ..Default::default()
        };
        let buffer = msg.encode_to_vec();
        Ok(self.ws.send_message(buffer.into()).await?)
    }

    /// Worker task that
    async fn run(
        mut self,
        mut sink: Sender<Result<ProvisioningStep, ProvisioningError>>,
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
                    // TODO: implement keep-alive?
                    Some(WebSocketStreamItem::KeepAliveRequest) => continue,
                    None => break,
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

    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<Option<ProvisioningStep>, ProvisioningError> {
        let msg = WebSocketMessage::decode(frame)?;
        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Request, Some(request), _) => {
                match request {
                    // step 1: we get a ProvisioningUUID that we need to build a
                    // registration link
                    WebSocketRequestMessage {
                        id,
                        verb,
                        path,
                        body,
                        ..
                    } if verb == Some("PUT".into())
                        && path == Some("/v1/address".into()) =>
                    {
                        let uuid: ProvisioningUuid =
                            prost::Message::decode(Bytes::from(body.unwrap()))?;
                        let mut provisioning_url =
                            Url::parse("sgnl://linkdevice").map_err(|e| {
                                ProvisioningError::WsError {
                                    reason: e.to_string(),
                                }
                            })?;
                        provisioning_url
                            .query_pairs_mut()
                            .append_pair("uuid", &uuid.uuid.unwrap())
                            .append_pair(
                                "pub_key",
                                &base64::encode(
                                    self.provisioning_cipher
                                        .public_key()
                                        .serialize(),
                                ),
                            );

                        // acknowledge
                        self.send_ok_response(id).await?;

                        Ok(Some(ProvisioningStep::Url(provisioning_url)))
                    },
                    // step 2: once the QR code is scanned by the (already
                    // validated) main device
                    // we get a ProvisionMessage, that contains a bunch of
                    // useful things
                    WebSocketRequestMessage {
                        id,
                        verb,
                        path,
                        body,
                        ..
                    } if verb == Some("PUT".into())
                        && path == Some("/v1/message".into()) =>
                    {
                        let provision_envelope: ProvisionEnvelope =
                            prost::Message::decode(Bytes::from(body.unwrap()))?;
                        let provision_message = self
                            .provisioning_cipher
                            .decrypt(provision_envelope)?;

                        // acknowledge
                        self.send_ok_response(id).await?;

                        Ok(Some(ProvisioningStep::Message(provision_message)))
                    },
                    _ => Err(ProvisioningError::WsError {
                        reason: "Incorrect request".into(),
                    }),
                }
            },
            _ => Err(ProvisioningError::WsError {
                reason: "Incorrect request".into(),
            }),
        }
    }

    pub fn stream(
        self,
    ) -> impl Stream<Item = Result<ProvisioningStep, ProvisioningError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|_| {
            log::info!("Sink closed, provisioning is done!");
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}
