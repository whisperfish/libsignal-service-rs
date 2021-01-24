use bytes::{Bytes, BytesMut};
use futures::{
    channel::mpsc::{self, Sender},
    prelude::*,
    stream::FuturesUnordered,
};
use hmac::{Hmac, Mac, NewMac};
use pin_project::pin_project;
use prost::Message;
use sha2::Sha256;
use url::Url;

use libsignal_protocol::{
    keys::{KeyPair, PublicKey},
    Context,
};

use crate::{
    envelope::{CIPHER_KEY_SIZE, IV_LENGTH, IV_OFFSET},
    messagepipe::{WebSocketService, WebSocketStreamItem},
    proto::{
        web_socket_message, ProvisionEnvelope, ProvisionMessage,
        ProvisioningUuid, WebSocketMessage, WebSocketRequestMessage,
        WebSocketResponseMessage,
    },
    push_service::ServiceError,
};

#[derive(Debug)]
enum CipherMode {
    Decrypt(KeyPair),
    Encrypt(PublicKey),
}

impl CipherMode {
    fn public(&self) -> PublicKey {
        match self {
            CipherMode::Decrypt(pair) => pair.public(),
            CipherMode::Encrypt(pub_key) => pub_key.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ProvisioningCipher {
    ctx: Context,
    key_material: CipherMode,
}

#[derive(thiserror::Error, Debug)]
pub enum ProvisioningError {
    #[error("Invalid provisioning data: {reason}")]
    InvalidData { reason: String },
    #[error("Protobuf decoding error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Websocket error: {reason}")]
    WsError { reason: String },
    #[error("Websocket closing: {reason}")]
    WsClosing { reason: String },
    #[error("Service error: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),
    #[error("ProvisioningCipher in encrypt-only mode")]
    EncryptOnlyProvisioningCipher,
}

impl ProvisioningCipher {
    pub fn new(ctx: Context) -> Result<Self, ProvisioningError> {
        let key_pair = libsignal_protocol::generate_key_pair(&ctx)?;
        Ok(Self {
            ctx,
            key_material: CipherMode::Decrypt(key_pair),
        })
    }

    pub fn from_public(ctx: Context, key: PublicKey) -> Self {
        Self {
            ctx,
            key_material: CipherMode::Encrypt(key),
        }
    }

    pub fn from_key_pair(ctx: Context, key_pair: KeyPair) -> Self {
        Self {
            ctx,
            key_material: CipherMode::Decrypt(key_pair),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key_material.public()
    }

    pub fn encrypt(
        &self,
        _msg: ProvisionMessage,
    ) -> Result<ProvisionEnvelope, ProvisioningError> {
        unimplemented!()
    }

    pub fn decrypt(
        &self,
        provision_envelope: ProvisionEnvelope,
    ) -> Result<ProvisionMessage, ProvisioningError> {
        let key_pair = match self.key_material {
            CipherMode::Decrypt(ref key_pair) => key_pair,
            CipherMode::Encrypt(_) => {
                return Err(ProvisioningError::EncryptOnlyProvisioningCipher);
            }
        };
        let master_ephemeral = PublicKey::decode_point(
            &self.ctx,
            &provision_envelope.public_key.expect("no public key"),
        )?;
        let body = provision_envelope
            .body
            .expect("no body in ProvisionMessage");
        if body[0] != 1 {
            return Err(ProvisioningError::InvalidData {
                reason: "Bad version number".into(),
            });
        }

        let iv = &body[IV_OFFSET..(IV_LENGTH + IV_OFFSET)];
        let mac = &body[(body.len() - 32)..];
        let cipher_text = &body[16 + 1..(body.len() - CIPHER_KEY_SIZE)];
        let iv_and_cipher_text = &body[0..(body.len() - CIPHER_KEY_SIZE)];
        debug_assert_eq!(iv.len(), IV_LENGTH);
        debug_assert_eq!(mac.len(), 32);

        let agreement =
            master_ephemeral.calculate_agreement(&key_pair.private())?;
        let hkdf = libsignal_protocol::create_hkdf(&self.ctx, 3)?;

        let shared_secrets = hkdf.derive_secrets(
            64,
            &agreement,
            &[],
            b"TextSecure Provisioning Message",
        )?;

        let parts1 = &shared_secrets[0..32];
        let parts2 = &shared_secrets[32..];

        let mut verifier = Hmac::<Sha256>::new_varkey(&parts2)
            .expect("HMAC can take any size key");
        verifier.update(&iv_and_cipher_text);
        let our_mac = verifier.finalize().into_bytes();
        debug_assert_eq!(our_mac.len(), mac.len());
        if &our_mac[..32] != mac {
            return Err(ProvisioningError::InvalidData {
                reason: "wrong MAC".into(),
            });
        }

        use aes::Aes256;
        // libsignal-service-java uses Pkcs5,
        // but that should not matter.
        // https://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding
        use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&parts1, &iv)
            .expect("initalization of CBC/AES/PKCS7");
        let input = cipher.decrypt_vec(cipher_text).expect("decryption");

        Ok(prost::Message::decode(Bytes::from(input))?)
    }
}

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
        ctx: &Context,
    ) -> Result<Self, ProvisioningError> {
        Ok(ProvisioningPipe {
            ws,
            stream,
            provisioning_cipher: ProvisioningCipher::new(ctx.clone())?,
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
        let mut buffer = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buffer).unwrap();
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
                        let mut provisioning_url = Url::parse("tsdevice://")
                            .map_err(|e| ProvisioningError::WsError {
                                reason: e.to_string(),
                            })?;
                        provisioning_url
                            .query_pairs_mut()
                            .append_pair("uuid", &uuid.uuid.unwrap())
                            .append_pair(
                                "pub_key",
                                &format!(
                                    "{}",
                                    self.provisioning_cipher.public_key()
                                ),
                            );

                        // acknowledge
                        self.send_ok_response(id).await?;

                        Ok(Some(ProvisioningStep::Url(provisioning_url)))
                    }
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
                    }
                    _ => Err(ProvisioningError::WsError {
                        reason: "Incorrect request".into(),
                    }),
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_provisioning_roundtrip() {
        let ctx = Context::default();
        let cipher = ProvisioningCipher::new(ctx.clone()).unwrap();
        let encrypt_cipher =
            ProvisioningCipher::from_public(ctx.clone(), cipher.public_key());

        assert_eq!(
            cipher.public_key(),
            encrypt_cipher.public_key(),
            "copy public key"
        );

        let msg = ProvisionMessage::default();
        let encrypted = encrypt_cipher.encrypt(msg.clone()).unwrap();

        assert!(matches!(
            encrypt_cipher.decrypt(encrypted.clone()),
            Err(ProvisioningError::EncryptOnlyProvisioningCipher)
        ));

        let decrypted = cipher.decrypt(encrypted).expect("decryptability");
        assert_eq!(msg, decrypted);
    }
}
