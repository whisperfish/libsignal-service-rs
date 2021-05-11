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
    prelude::{MessageSender, MessageSenderError},
    push_service::{PushService, ServiceError},
    sealed_session_cipher::UnidentifiedAccess,
    sender::{
        create_multi_device_sent_transcript_content, OutgoingPushMessages,
        SendMessageResponse, SentMessage,
    },
    session_store::SessionStoreExt,
    ServiceAddress,
};

pub enum WebSocketStreamItem {
    Message(Bytes),
    KeepAliveRequest,
}

pub struct MessageToSend {
    pub recipients: Vec<ServiceAddress>,
    pub unidentified_access: Option<UnidentifiedAccess>,
    pub message: ContentBody,
    pub timestamp: u64,
    pub online: bool,
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
        impl Future<Output = Result<WebSocketResponseMessage, MessageSenderError>>,
        MessageSenderError,
    > {
        let id = r.id;

        self.transmit_request(r).await?;

        let (sink, send) = oneshot::channel();

        if let Some(id) = id {
            self.requests.insert(id, sink);
            Ok(send.map_err(|_| {
                ServiceError::WsClosing {
                    reason: "WebSocket closing while sending request.".into(),
                }
                .into()
            }))
        } else {
            Err(ServiceError::InvalidFrameError {
                reason: "Send request without ID".into(),
            }
            .into())
        }
    }

    /// Worker task that runs the message pipe loop which concurrently looks for incoming message to process
    /// and processes frames received in the web-socket
    async fn run(
        mut self,
        mut outgoing_sender: Sender<Result<Envelope, MessageSenderError>>,
        incoming_sender: Sender<MessageToSend>,
        mut incoming_receiver: Receiver<MessageToSend>,
    ) -> Result<(), mpsc::SendError> {
        use futures::future::LocalBoxFuture;

        let inner_local_address = self.message_sender.local_address.clone();

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
                    if let Some(MessageToSend { recipients, unidentified_access, message, timestamp, online }) = message_to_send {
                        // this is mirrored logic from MessageSender::send_message
                        let mut response_futures = vec![];
                        let mut inner_outgoing_sender = outgoing_sender.clone();
                        let mut inner_incoming_sender = incoming_sender.clone();
                        for recipient in recipients.into_iter() {
                            let message = message.clone();
                            match self.send_message(&recipient, unidentified_access.as_ref(), message, timestamp, online).await {
                                Ok(response_future) => {
                                    response_futures.push((recipient, response_future));
                                }
                                Err(e) => {
                                    outgoing_sender.send(Err(e)).await?;
                                }
                            }
                        }

                        // we will wait for the result in the background
                        let inner_local_address = inner_local_address.clone();

                        // FIXME: this means we can't easily delete the mismatched devices...
                        // since we can't access the session-store here
                        background_work.push(async move {
                            let mut needs_sync_in_results = false;
                            let mut results = vec![];
                            for (recipient, response_fut) in response_futures {
                                let result = Self::process_send_response(recipient, unidentified_access.as_ref(), response_fut).await;
                                match result {
                                    Ok(SentMessage { needs_sync, .. }) => {
                                        if needs_sync {
                                            needs_sync_in_results = true;
                                        }
                                        results.push(result);
                                    }
                                    Err(e) => {
                                        // FIXME: if the error was mismatched devices here, we need to submit a message
                                        // for the loop to delete the offending sessions

                                        inner_outgoing_sender.send(Err(e)).await.expect("working outgoing sender"); }
                                };
                            }

                            if let ContentBody::DataMessage(data_message) = message {
                                if needs_sync_in_results {
                                    let sync_message: ContentBody = create_multi_device_sent_transcript_content(
                                        None,
                                        Some(data_message),
                                        timestamp,
                                        &results,
                                    ).into();
                                    log::debug!("submitting sync message from background");

                                    // inject the sync message in the message pipe
                                    inner_incoming_sender.send(MessageToSend {
                                        recipients: vec![inner_local_address],
                                        unidentified_access,
                                        message: sync_message,
                                        timestamp,
                                        online,
                                    }).await.expect("working incoming sender");
                                }
                            }

                        }.boxed_local());
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
        content_body: impl Into<ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Result<
        impl Future<Output = Result<WebSocketResponseMessage, MessageSenderError>>,
        MessageSenderError,
    > {
        use crate::proto::data_message::Flags;

        let content_body = content_body.into();
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
            .await?;

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

        let response_fut = self.send_request(message_request).await;

        // check if we need to end the session after sending this message
        match &content_body {
            ContentBody::DataMessage(message)
                if message.flags == Some(Flags::EndSession as u32) =>
            {
                log::debug!("ending session with {}", recipient);
                if let Some(ref uuid) = recipient.uuid {
                    self.message_sender
                        .session_store
                        .delete_all_sessions(&uuid.to_string())
                        .await?;
                }
                if let Some(e164) = recipient.e164() {
                    self.message_sender
                        .session_store
                        .delete_all_sessions(&e164)
                        .await?;
                }
            }
            _ => (),
        };

        response_fut
    }

    async fn process_send_response(
        recipient: ServiceAddress,
        unidentified_access: Option<&UnidentifiedAccess>,
        response_fut: impl Future<
            Output = Result<WebSocketResponseMessage, MessageSenderError>,
        >,
    ) -> Result<SentMessage, MessageSenderError> {
        match response_fut.await {
            Ok(WebSocketResponseMessage {
                status: Some(status),
                body: Some(body),
                ..
            }) if status == 200 => match serde_json::from_slice(&body) {
                Ok(SendMessageResponse { needs_sync }) => Ok(SentMessage {
                    recipient,
                    unidentified: unidentified_access.is_some(),
                    needs_sync,
                }),
                Err(e) => {
                    log::error!("Failed to decode HTTP 200 response: {}", e);
                    Err(ServiceError::JsonDecodeError {
                        reason: e.to_string(),
                    }
                    .into())
                }
            },

            Ok(WebSocketResponseMessage {
                status: Some(status),
                body: Some(body),
                ..
            }) if status == 409 => match serde_json::from_slice(&body) {
                Ok(mismatched_devices) => {
                    Err(ServiceError::MismatchedDevicesException(
                        mismatched_devices,
                    )
                    .into())
                }
                Err(e) => {
                    log::error!("Failed to decode HTTP 409 response: {}", e);
                    Err(ServiceError::JsonDecodeError {
                        reason: e.to_string(),
                    }
                    .into())
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
                }
                .into())
            }
            Ok(_) => Err(ServiceError::WsError {
                reason: "malformed websocket response".into(),
            }
            .into()),
            Err(e) => Err(e),
        }
    }

    async fn send_keep_alive(
        &mut self,
    ) -> Result<
        impl Future<Output = Result<(), MessageSenderError>>,
        MessageSenderError,
    > {
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
                }
                .into())
            }
        })
    }

    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<Option<Envelope>, MessageSenderError> {
        let msg = WebSocketMessage::decode(frame)
            .map_err(ServiceError::ProtobufDecodeError)?;
        log::trace!("Decoded {:?}", msg);

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrameError {
                reason: "Unknown frame type".into(),
            }
            .into()),
            (Type::Request, Some(request), _) => {
                // Java: MessagePipe::read
                let response = WebSocketResponseMessage::from_request(&request);

                let result = if request.is_signal_service_envelope() {
                    let body = if let Some(body) = request.body.as_ref() {
                        body
                    } else {
                        return Err(ServiceError::InvalidFrameError {
                            reason: "Request without body.".into(),
                        }
                        .into());
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
            }
            .into()),
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
            }
            .into()),
        }
    }

    /// Returns the stream of `Envelope`s
    ///
    /// Envelopes yielded are acknowledged.
    pub fn split(
        self,
    ) -> (
        impl Sink<MessageToSend>,
        impl Stream<Item = Result<Envelope, MessageSenderError>>,
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
