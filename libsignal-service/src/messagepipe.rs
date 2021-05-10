use std::collections::HashMap;

use bytes::{Bytes, BytesMut};
use futures::{
    channel::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
    prelude::*,
    stream::{FusedStream, FuturesUnordered},
};
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore,
};
use pin_project::pin_project;
use prost::Message;
use rand::{CryptoRng, Rng};

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::{
    content::ContentBody,
    prelude::MessageSender,
    push_service::{PushService, ServiceError},
    sealed_session_cipher::UnidentifiedAccess,
    sender::{
        create_multi_device_sent_transcript_content, MessageToSend,
        OutgoingPushMessages, SendMessageResponse,
    },
    session_store::SessionStoreExt,
    ServiceAddress,
};

pub enum WebSocketStreamItem {
    Message(Bytes),
    KeepAliveRequest,
}

#[async_trait::async_trait(?Send)]
pub trait WebSocketService {
    type Stream: FusedStream<Item = WebSocketStreamItem> + Unpin;

    async fn send_message(&mut self, msg: Bytes) -> Result<(), ServiceError>;
}

#[pin_project]
pub struct MessagePipe<WS: WebSocketService, Service, S, I, SP, P, R> {
    ws: WS,
    #[pin]
    stream: WS::Stream,
    credentials: ServiceCredentials,
    requests: HashMap<u64, oneshot::Sender<WebSocketResponseMessage>>,
    message_sender: MessageSender<Service, S, I, SP, P, R>,
}

impl<WS: WebSocketService, Service, S, I, SP, P, R>
    MessagePipe<WS, Service, S, I, SP, P, R>
where
    Service: PushService + Clone,
    S: SessionStore + SessionStoreExt + Clone,
    I: IdentityKeyStore + Clone,
    SP: SignedPreKeyStore + Clone,
    P: PreKeyStore + Clone,
    R: Rng + CryptoRng + Clone,
{
    pub fn from_socket(
        ws: WS,
        stream: WS::Stream,
        credentials: ServiceCredentials,
        message_sender: MessageSender<Service, S, I, SP, P, R>,
    ) -> Self {
        MessagePipe {
            ws,
            stream,
            credentials,
            requests: HashMap::new(),
            message_sender,
        }
    }

    async fn send_response(
        &mut self,
        r: WebSocketResponseMessage,
    ) -> Result<(), ServiceError> {
        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Response.into()),
            response: Some(r),
            ..Default::default()
        };
        let mut buffer = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buffer).unwrap();
        self.ws.send_message(buffer.into()).await
    }

    /// Sends a request without returning a response.
    async fn transmit_request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<(), ServiceError> {
        log::trace!("Sending request {:?}", r);
        let msg = WebSocketMessage {
            r#type: Some(web_socket_message::Type::Request.into()),
            request: Some(r),
            ..Default::default()
        };
        let mut buffer = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buffer).unwrap();
        self.ws.send_message(buffer.into()).await?;
        log::trace!("request on route.");
        Ok(())
    }

    /// Send request and returns the response as a *nested* Future.
    ///
    /// The outer Future sends the request, the inner Future resolves to the
    /// response.
    pub async fn send_request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<
        impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>,
        ServiceError,
    > {
        let id = r.id;

        self.transmit_request(r).await?;

        let (sink, send) = oneshot::channel();

        if let Some(id) = id {
            self.requests.insert(id, sink);
            Ok(send.map_err(|_| ServiceError::WsClosing {
                reason: "WebSocket closing while sending request.".into(),
            }))
        } else {
            Err(ServiceError::InvalidFrameError {
                reason: "Send request without ID".into(),
            })
        }
    }

    /// Worker task that
    async fn run(
        mut self,
        mut outgoing_sender: Sender<Result<Envelope, ServiceError>>,
        incoming_sender: Sender<MessageToSend>,
        mut incoming_receiver: Receiver<MessageToSend>,
    ) -> Result<(), mpsc::SendError> {
        use futures::future::LocalBoxFuture;

        // This is a runtime-agnostic, poor man's `::spawn(Future<Output=()>)`.
        let mut background_work = FuturesUnordered::<LocalBoxFuture<()>>::new();
        // a pending task is added, as to never end the background worker until
        // it's dropped.
        background_work.push(futures::future::pending().boxed_local());

        loop {
            futures::select! {
                // When we receive a new message from Signal's servers
                // WebsocketConnection::onMessage(ByteString)
                frame = self.stream.next() => match frame {
                    Some(WebSocketStreamItem::Message(frame)) => {
                        let env = self.process_frame(frame).await.transpose();
                        if let Some(env) = env {
                            outgoing_sender.send(env).await?;
                        }
                    },
                    Some(WebSocketStreamItem::KeepAliveRequest) => {
                        let request = self.send_keep_alive().await;
                        match request {
                            Ok(request) => {
                                let request = request.map(|response| {
                                    if let Err(e) = response {
                                        log::warn!("Error from keep alive: {:?}", e);
                                    }
                                });
                                background_work.push(request.boxed_local());
                            },
                            Err(e) => log::warn!("Could not send keep alive: {}", e),
                        }
                    },
                    None => {
                        log::debug!("WebSocket stream ended.");
                        break;
                    },
                },
                // When we have a message to send (from either the outside, or re-injected)
                message_to_send = incoming_receiver.next() => {
                    let mut inner_outgoing_sender = outgoing_sender.clone();
                    let mut inner_incoming_sender = incoming_sender.clone();
                    let local_address = self.message_sender.local_address.clone();
                    if let Some(MessageToSend { recipient, unidentified_access, content_body, timestamp, online }) = message_to_send {
                        // this is mirrored logic from MessageSender::send_message
                        match self.send_message(&recipient, unidentified_access.as_ref(), &content_body, timestamp, online).await {
                            Ok(response_fut) => {
                                // we want to wait for the response in the background to avoid blocking the message loop
                                background_work.push(async move {
                                    match Self::process_send_response(recipient, content_body, timestamp, response_fut).await {
                                        Ok(Some(content_body)) => {
                                            // we re-inject the new sync message in the pipe!
                                            inner_incoming_sender.send(MessageToSend {
                                                recipient: local_address,
                                                unidentified_access: None,
                                                content_body,
                                                timestamp,
                                                online: false,
                                            }).await.expect("working incoming sender");
                                        }
                                        Err(e) => { inner_outgoing_sender.send(Err(e)).await.expect("working outgoing sender"); }
                                        _ => (),
                                    };
                                }.boxed_local());
                            }
                            Err(e) => {
                                outgoing_sender.send(Err(e)).await?;
                            }
                        }
                }

                }
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

    async fn send_message(
        &mut self,
        recipient: &ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        content_body: &ContentBody,
        timestamp: u64,
        online: bool,
    ) -> Result<
        impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>,
        ServiceError,
    > {
        use crate::proto::data_message::Flags;

        // TODO: check what we should do here
        // this should be possible when we factor the common parts between `MessageSender` and `MessagePipe`
        // (mostly the session handling part)
        let _end_session = match &content_body {
            ContentBody::DataMessage(message) => {
                message.flags == Some(Flags::EndSession as u32)
            }
            _ => false,
        };

        let content = content_body.clone().into_proto();
        let mut content_bytes = Vec::with_capacity(content.encoded_len());
        content
            .encode(&mut content_bytes)
            .expect("infallible message encoding");

        // here we need to transform our MessageToSend to a OutgoingPushMessages
        let messages = self
            .message_sender
            .create_encrypted_messages(
                &recipient,
                unidentified_access,
                &content_bytes,
            )
            .await
            .unwrap();

        let destination = recipient.identifier();
        let messages = OutgoingPushMessages {
            destination,
            timestamp,
            messages,
            online,
        };

        let message_request = WebSocketRequestMessage {
            id: Some(timestamp),
            path: Some(format!("/v1/messages/{}", messages.destination)),
            verb: Some("PUT".into()),
            body: Some(serde_json::to_vec(&messages).unwrap()),
            headers: vec!["content-type:application/json".to_string()],
        };

        self.send_request(message_request).await
    }

    async fn process_send_response(
        recipient: ServiceAddress,
        content_body: ContentBody,
        timestamp: u64,
        response_fut: impl Future<
            Output = Result<WebSocketResponseMessage, ServiceError>,
        >,
    ) -> Result<Option<ContentBody>, ServiceError> {
        match response_fut.await {
            Ok(WebSocketResponseMessage {
                status: Some(status),
                body: Some(body),
                ..
            }) if status == 200 => {
                match (content_body, serde_json::from_slice(&body)) {
                    (
                        ContentBody::DataMessage(message),
                        Ok(SendMessageResponse { needs_sync, .. }),
                    ) if needs_sync => {
                        // TODO: also implement the selection logic for the recipient of the sync message
                        // following sending a group message
                        // see: https://github.com/whisperfish/libsignal-service-rs/issues/75
                        // and sender.rs:418
                        log::debug!("sending multi-device sync message");
                        let sync_message =
                            create_multi_device_sent_transcript_content(
                                Some(&recipient),
                                Some(message),
                                timestamp,
                            );
                        Ok(Some(sync_message))
                    }
                    (_, Err(e)) => {
                        log::error!(
                            "Failed to decode HTTP 200 response: {}",
                            e
                        );
                        Err(ServiceError::UnhandledResponseCode {
                            http_code: 200,
                        })
                    }
                    (content_body, response) => {
                        eprintln!("{:?}, {:?}", content_body, response);
                        Ok(None)
                    }
                }
            }

            Ok(WebSocketResponseMessage {
                status: Some(status),
                body: Some(body),
                ..
            }) if status == 409 => match serde_json::from_slice(&body) {
                Ok(mismatched_devices) => {
                    Err(ServiceError::MismatchedDevicesException(
                        mismatched_devices,
                    ))
                }
                Err(e) => {
                    log::error!("Failed to decode HTTP 409 response: {}", e);
                    Err(ServiceError::UnhandledResponseCode { http_code: 409 })
                }
            },
            Ok(WebSocketResponseMessage {
                status: Some(status),
                body,
                ..
            }) => {
                // unhandled HTTP status
                log::trace!("Unhandled response with body: {:?}", body);
                Err(ServiceError::UnhandledResponseCode {
                    http_code: status as u16,
                })
            }
            Ok(_) => Err(ServiceError::WsError {
                reason: "malformed websocket response".into(),
            }),
            Err(e) => Err(e),
        }
    }

    async fn send_keep_alive(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), ServiceError>>, ServiceError>
    {
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
        let request = self.send_request(request).await?;
        Ok(async move {
            let response = request.await?;
            if response.status() == 200 {
                Ok(())
            } else {
                log::warn!(
                    "Response code for keep-alive is not 200: {:?}",
                    response
                );
                Err(ServiceError::UnhandledResponseCode {
                    http_code: response.status() as u16,
                })
            }
        })
    }

    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<Option<Envelope>, ServiceError> {
        let msg = WebSocketMessage::decode(frame)?;
        log::trace!("Decoded {:?}", msg);

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrameError {
                reason: "Unknown frame type".into(),
            }),
            (Type::Request, Some(request), _) => {
                // Java: MessagePipe::read
                let response = WebSocketResponseMessage::from_request(&request);

                let result = if request.is_signal_service_envelope() {
                    let body = if let Some(body) = request.body.as_ref() {
                        body
                    } else {
                        return Err(ServiceError::InvalidFrameError {
                            reason: "Request without body.".into(),
                        });
                    };
                    Some(Envelope::decrypt(
                        body,
                        &self.credentials.signaling_key.as_ref().expect(
                            "signaling_key required to decrypt envelopes",
                        ),
                        request.is_signal_key_encrypted(),
                    )?)
                } else {
                    None
                };

                if let Err(e) = self.send_response(response).await {
                    log::error!("Could not send response: {}", e);
                }

                Ok(result)
            }
            (Type::Request, None, _) => Err(ServiceError::InvalidFrameError {
                reason: "Type was request, but does not contain request."
                    .into(),
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) = self.requests.remove(&id) {
                        if let Err(e) = responder.send(response) {
                            log::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else {
                        log::warn!(
                            "Response for non existing request: {:?}",
                            response
                        );
                    }
                }

                Ok(None)
            }
            (Type::Response, _, None) => Err(ServiceError::InvalidFrameError {
                reason: "Type was response, but does not contain response."
                    .into(),
            }),
        }
    }

    /// Returns the stream of `Envelope`s
    ///
    /// Envelopes yielded are acknowledged.
    pub fn split(
        self,
    ) -> (
        impl Sink<MessageToSend>,
        impl Stream<Item = Result<Envelope, ServiceError>>,
    ) {
        let (sink, stream) = mpsc::channel(1);
        let (message_sender, message_receiver) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self
            .run(sink, message_sender.clone(), message_receiver)
            .map(|e| {
                log::info!("Sink was closed. Reason: {:?}", e);
                None
            });

        let combined = futures::stream::select(stream, runner.into_stream());
        (message_sender, combined.filter_map(|x| async { x }))
    }
}

/// WebSocketService that panics on every request, mainly for example code.
pub struct PanicingWebSocketService;

#[async_trait::async_trait(?Send)]
impl WebSocketService for PanicingWebSocketService {
    type Stream = futures::channel::mpsc::Receiver<WebSocketStreamItem>;

    async fn send_message(&mut self, _msg: Bytes) -> Result<(), ServiceError> {
        unimplemented!();
    }
}
