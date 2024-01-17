use base64::prelude::*;
use bytes::Bytes;
use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
};
use url::Url;

pub use crate::proto::{ProvisionEnvelope, ProvisionMessage};

use crate::{
    proto::{
        ProvisioningUuid, WebSocketRequestMessage, WebSocketResponseMessage,
    },
    provisioning::ProvisioningError,
    websocket::SignalWebSocket,
};

use super::cipher::ProvisioningCipher;

pub struct ProvisioningPipe {
    ws: SignalWebSocket,
    provisioning_cipher: ProvisioningCipher,
}

#[derive(Debug)]
pub enum ProvisioningStep {
    Url(Url),
    Message(ProvisionMessage),
}

impl ProvisioningPipe {
    pub fn from_socket(ws: SignalWebSocket) -> Result<Self, ProvisioningError> {
        Ok(ProvisioningPipe {
            ws,
            provisioning_cipher: ProvisioningCipher::generate(
                &mut rand::thread_rng(),
            )?,
        })
    }

    /// Worker task that
    async fn run(
        mut self,
        mut sink: Sender<Result<ProvisioningStep, ProvisioningError>>,
    ) -> Result<(), mpsc::SendError> {
        let mut ws = self.ws.clone();
        let mut stream = ws
            .take_request_stream()
            .expect("web socket request handler not in use");
        while let Some((req, responder)) = stream.next().await {
            let env = self.process_request(req, responder).await.transpose();
            if let Some(env) = env {
                sink.send(env).await?;
            }
        }
        ws.return_request_stream(stream);

        Ok(())
    }

    async fn process_request(
        &mut self,
        request: WebSocketRequestMessage,
        responder: oneshot::Sender<WebSocketResponseMessage>,
    ) -> Result<Option<ProvisioningStep>, ProvisioningError> {
        let ok = WebSocketResponseMessage {
            id: request.id,
            status: Some(200),
            message: Some("OK".into()),
            body: None,
            headers: vec![],
        };

        match request {
            // step 1: we get a ProvisioningUUID that we need to build a
            // registration link
            WebSocketRequestMessage {
                id: _,
                verb,
                path,
                body,
                ..
            } if verb == Some("PUT".into())
                && path == Some("/v1/address".into()) =>
            {
                let uuid: ProvisioningUuid =
                    prost::Message::decode(Bytes::from(body.unwrap()))?;
                let mut provisioning_url = Url::parse("sgnl://linkdevice")
                    .map_err(|e| ProvisioningError::WsError {
                        reason: e.to_string(),
                    })?;
                provisioning_url
                    .query_pairs_mut()
                    .append_pair("uuid", &uuid.uuid.unwrap())
                    .append_pair(
                        "pub_key",
                        &BASE64_STANDARD.encode(
                            self.provisioning_cipher.public_key().serialize(),
                        ),
                    );

                // acknowledge
                responder.send(ok).map_err(|_| {
                    ProvisioningError::WsClosing {
                        reason: "could not respond to provision request".into(),
                    }
                })?;

                Ok(Some(ProvisioningStep::Url(provisioning_url)))
            },
            // step 2: once the QR code is scanned by the (already
            // validated) main device
            // we get a ProvisionMessage, that contains a bunch of
            // useful things
            WebSocketRequestMessage {
                id: _,
                verb,
                path,
                body,
                ..
            } if verb == Some("PUT".into())
                && path == Some("/v1/message".into()) =>
            {
                let provision_envelope: ProvisionEnvelope =
                    prost::Message::decode(Bytes::from(body.unwrap()))?;
                let provision_message =
                    self.provisioning_cipher.decrypt(provision_envelope)?;

                // acknowledge
                responder.send(ok).map_err(|_| {
                    ProvisioningError::WsClosing {
                        reason: "could not respond to provision request".into(),
                    }
                })?;

                Ok(Some(ProvisioningStep::Message(provision_message)))
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
            tracing::info!("Sink closed, provisioning is done!");
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}
