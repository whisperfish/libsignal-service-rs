use aes::cipher::generic_array::GenericArray;
use aes_ctr::{
    cipher::stream::{NewStreamCipher, SyncStreamCipher},
    Aes256Ctr,
};

use hmac::{Hmac, Mac, NewMac};
use libsignal_protocol::{
    keys::PrivateKey,
    keys::{IdentityKeyPair, PublicKey},
    messages::CiphertextType,
    messages::PreKeySignalMessage,
    messages::SignalMessage,
    Address, Context, Deserializable, SessionCipher, StoreContext,
};
use log::error;
use sha2::Sha256;

use crate::ServiceAddress;

#[derive(Debug, thiserror::Error)]
pub enum SealedSessionError {
    #[error("Unknown version {0}")]
    InvalidMetadataVersionError(u8),

    #[error("{0}")]
    InvalidMetadataMessageError(String),

    #[error("Invalid MAC: {0}")]
    InvalidMacError(MacError),

    #[error("Invalid certificate (missing fields)")]
    InvalidCertificate,

    #[error("Failed to decode protobuf {0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Protocol error {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum MacError {
    #[error("Ciphertext not long enough ({0} bytes) for MAC")]
    CiphertextNotLongEnough(usize),
    #[error("Bad MAC")]
    BadMac,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedSessionCipher {
    identity: IdentityKeyPair,
    context: Context,
    store_context: StoreContext,
    local_address: ServiceAddress,
    certificate_validator: CertificateValidator,
}

#[derive(Debug, Clone)]
struct UnidentifiedSenderMessage {
    version: u8,
    ephemeral: PublicKey,
    encrypted_static: Vec<u8>,
    encrypted_message: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnidentifiedSenderMessageContent {
    r#type: CiphertextType,
    sender_certificate: SenderCertificate,
    content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderCertificate {
    signer: ServerCertificate,
    key: PublicKey,
    sender_device_id: i32,
    sender_uuid: Option<String>,
    sender_e164: Option<String>,
    expiration: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SenderCertificate {
    // XXX: Result
    fn sender(&self) -> String {
        match self
            .sender_e164
            .as_ref()
            .or_else(|| self.sender_uuid.as_ref())
        {
            Some(r) => r.clone(),
            None => "".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerCertificate {
    key_id: u32,
    key: PublicKey,
    // serialized: Vec<u8>, // I suppose this has some significance, but it's consumed
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Clone)]
struct EphemeralKeys {
    chain_key: Vec<u8>,
    cipher_key: Vec<u8>,
    mac_key: Vec<u8>,
}

#[derive(Debug, Clone)]
struct StaticKeys {
    cipher_key: Vec<u8>,
    mac_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CertificateValidator {
    pub trust_root: PublicKey,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct DecryptionResult {
    pub sender_uuid: Option<String>,
    pub sender_e164: Option<String>,
    pub device_id: i32,
    pub padded_message: Vec<u8>,
    pub version: u32,
}

impl UnidentifiedSenderMessage {
    const CIPHERTEXT_VERSION: u8 = 1;

    fn new(
        context: &Context,
        serialized: &[u8],
    ) -> Result<Self, SealedSessionError> {
        let version = (serialized[0] & 0xFF) >> 4;
        if version > Self::CIPHERTEXT_VERSION {
            return Err(SealedSessionError::InvalidMetadataVersionError(
                version,
            ));
        }

        let unidentified_sender_message: crate::proto::UnidentifiedSenderMessage =
            prost::Message::decode(&serialized[1..serialized.len()])?;

        match (
            unidentified_sender_message.ephemeral_public,
            unidentified_sender_message.encrypted_static,
            unidentified_sender_message.encrypted_message,
        ) {
            (
                Some(ephemeral_public),
                Some(encrypted_static),
                Some(encrypted_message),
            ) => Ok(Self {
                version,
                ephemeral: PublicKey::decode_point(
                    &context,
                    &ephemeral_public,
                )?,
                encrypted_static,
                encrypted_message,
            }),
            _ => Err(SealedSessionError::InvalidMetadataMessageError(
                "Missing fields".into(),
            )),
        }
    }
}

impl SealedSessionCipher {
    pub(crate) fn new(
        identity: IdentityKeyPair,
        context: Context,
        store_context: StoreContext,
        local_address: ServiceAddress,
        certificate_validator: CertificateValidator,
    ) -> Self {
        Self {
            identity,
            context,
            store_context,
            local_address,
            certificate_validator,
        }
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        timestamp: u64,
    ) -> Result<DecryptionResult, SealedSessionError> {
        let wrapper =
            UnidentifiedSenderMessage::new(&self.context, ciphertext)?;

        let ephemeral_salt = [
            "UnidentifiedDelivery".as_bytes(),
            self.identity.public().to_bytes()?.as_slice(),
            wrapper.ephemeral.to_bytes()?.as_slice(),
        ]
        .concat();

        let ephemeral_keys = self.calculate_ephemeral_keys(
            &wrapper.ephemeral,
            &self.identity.private(),
            &ephemeral_salt,
        )?;

        let static_key_bytes = Self::decrypt_bytes(
            &ephemeral_keys.cipher_key,
            &ephemeral_keys.mac_key,
            &wrapper.encrypted_static,
        )?;

        let static_key =
            PublicKey::decode_point(&self.context, &static_key_bytes)?;
        let static_salt =
            [ephemeral_keys.chain_key, wrapper.encrypted_static].concat();
        let static_keys = self.calculate_static_keys(
            &static_key,
            &self.identity.private(),
            &static_salt,
        )?;

        let message_bytes = Self::decrypt_bytes(
            &static_keys.cipher_key,
            &static_keys.mac_key,
            &wrapper.encrypted_message,
        )?;

        let content = UnidentifiedSenderMessageContent::try_from(
            &self.context,
            message_bytes.as_slice(),
        )?;
        self.certificate_validator
            .validate(&content.sender_certificate, timestamp)?;

        let (padded_message, version) =
            self.decrypt_message_content(&content)?;
        Ok(DecryptionResult {
            padded_message,
            version,
            sender_uuid: content.sender_certificate.sender_uuid,
            sender_e164: content.sender_certificate.sender_e164,
            device_id: content.sender_certificate.sender_device_id,
        })
    }

    fn calculate_ephemeral_keys(
        &self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        salt: &[u8],
    ) -> Result<EphemeralKeys, SealedSessionError> {
        let ephemeral_secret = public_key.calculate_agreement(private_key)?;
        let ephemeral_derived = libsignal_protocol::create_hkdf(
            &self.context,
            3,
        )?
        .derive_secrets(96, &ephemeral_secret, salt, &[])?;
        Ok(EphemeralKeys {
            chain_key: ephemeral_derived[0..32].into(),
            cipher_key: ephemeral_derived[32..64].into(),
            mac_key: ephemeral_derived[64..96].into(),
        })
    }

    fn calculate_static_keys(
        &self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        salt: &[u8],
    ) -> Result<StaticKeys, SealedSessionError> {
        let static_secret = public_key.calculate_agreement(private_key)?;
        let static_derived = libsignal_protocol::create_hkdf(&self.context, 3)?
            .derive_secrets(96, &static_secret, salt, &[])?;
        Ok(StaticKeys {
            cipher_key: static_derived[32..64].into(),
            mac_key: static_derived[64..96].into(),
        })
    }

    fn decrypt_bytes(
        cipher_key: &[u8],
        mac_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SealedSessionError> {
        if ciphertext.len() < 10 {
            return Err(SealedSessionError::InvalidMacError(
                MacError::CiphertextNotLongEnough(ciphertext.len()),
            ));
        }

        let (ciphertext_part1, their_mac) =
            ciphertext.split_at(ciphertext.len() - 10);

        let mut verifier = Hmac::<Sha256>::new_varkey(&mac_key)
            .expect("failed to create HMAC-SHA256");
        verifier.update(&ciphertext_part1);
        let digest = verifier.finalize().into_bytes();
        let our_mac = &digest[0..10];

        if our_mac != their_mac {
            return Err(SealedSessionError::InvalidMacError(MacError::BadMac));
        }

        let key = GenericArray::from_slice(cipher_key);
        let nonce = GenericArray::from_slice(&[0u8; 16]);

        let mut decrypted = ciphertext_part1.to_vec();
        let mut cipher = Aes256Ctr::new(key, nonce);
        cipher.apply_keystream(&mut decrypted);

        Ok(decrypted)
    }

    fn get_preferred_address(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<Address, SealedSessionError> {
        if let Some(ref sender_uuid) = certificate.sender_uuid {
            let address =
                Address::new(sender_uuid, certificate.sender_device_id as i32);
            if self.store_context.contains_session(&address)? {
                return Ok(address);
            }
        } else if let Some(ref sender_e164) = certificate.sender_e164 {
            let address =
                Address::new(sender_e164, certificate.sender_device_id as i32);
            if self.store_context.contains_session(&address)? {
                return Ok(address);
            }
        }

        Ok(Address::new(
            certificate.sender(),
            certificate.sender_device_id as i32,
        ))
    }

    fn decrypt_message_content(
        &self,
        message: &UnidentifiedSenderMessageContent,
    ) -> Result<(Vec<u8>, u32), SealedSessionError> {
        let sender = self.get_preferred_address(&message.sender_certificate)?;
        let session_cipher =
            SessionCipher::new(&self.context, &self.store_context, &sender)?;
        let msg = match message.r#type {
            CiphertextType::Signal => {
                let msg = session_cipher.decrypt_message(
                    &SignalMessage::deserialize(
                        &self.context,
                        &message.content,
                    )?,
                )?;
                msg.as_slice().to_vec()
            }
            CiphertextType::PreKey => {
                let msg = session_cipher.decrypt_pre_key_message(
                    &PreKeySignalMessage::deserialize(
                        &self.context,
                        &message.content,
                    )?,
                )?;
                msg.as_slice().to_vec()
            }
            _ => unreachable!("unknown message from unidentified sender type"),
        };

        let version = session_cipher.get_session_version()?;
        Ok((msg, version))
    }
}

impl UnidentifiedSenderMessageContent {
    fn try_from(
        context: &Context,
        serialized: &[u8],
    ) -> Result<Self, SealedSessionError> {
        use crate::proto::unidentified_sender_message::{self, message};

        let message: unidentified_sender_message::Message =
            prost::Message::decode(serialized)?;

        match (message.r#type, message.sender_certificate, message.content) {
            (Some(message_type), Some(sender_certificate), Some(content)) => {
                Ok(Self {
                    r#type: match message::Type::from_i32(message_type) {
                        Some(message::Type::Message) => CiphertextType::Signal,
                        Some(message::Type::PrekeyMessage) => {
                            CiphertextType::PreKey
                        }
                        _ => {
                            return Err(
                                SealedSessionError::InvalidMetadataMessageError(
                                    format!(
                                        "Wrong message type ({})",
                                        message::Type::from_i32(message_type)
                                    ),
                                ),
                            )
                        }
                    },
                    sender_certificate: SenderCertificate::try_from(
                        &context,
                        sender_certificate,
                    )?,
                    content,
                })
            }
            _ => Err(SealedSessionError::InvalidMetadataMessageError(
                "Missing fields".into(),
            )),
        }
    }
}

impl SenderCertificate {
    fn try_from(
        context: &Context,
        wrapper: crate::proto::SenderCertificate,
    ) -> Result<Self, SealedSessionError> {
        use crate::proto::sender_certificate::Certificate;
        use prost::Message;
        match (wrapper.signature, wrapper.certificate) {
            (Some(signature), Some(certificate)) => {
                let Certificate {
                    sender_e164,
                    sender_uuid,
                    sender_device,
                    expires,
                    identity_key,
                    signer,
                } = Message::decode(&certificate[..])?;
                match (sender_device, expires, identity_key, signer) {
                    (
                        Some(sender_device_id),
                        Some(expires),
                        Some(identity_key),
                        Some(signer),
                    ) => {
                        if sender_e164.is_none() && sender_uuid.is_none() {
                            return Err(SealedSessionError::InvalidCertificate);
                        }

                        Ok(Self {
                            signer: ServerCertificate::try_from(
                                &context, signer,
                            )?,
                            key: PublicKey::decode_point(
                                &context,
                                &identity_key,
                            )?,
                            sender_e164,
                            sender_uuid,
                            sender_device_id: sender_device_id as i32,
                            expiration: expires,
                            certificate,
                            signature,
                        })
                    }
                    _ => Err(SealedSessionError::InvalidCertificate),
                }
            }
            _ => Err(SealedSessionError::InvalidCertificate),
        }
    }
}

impl ServerCertificate {
    fn try_from(
        context: &Context,
        wrapper: crate::proto::ServerCertificate,
    ) -> Result<Self, SealedSessionError> {
        use crate::proto::server_certificate;
        use prost::Message;

        match (wrapper.certificate, wrapper.signature) {
            (Some(certificate), Some(signature)) => {
                let server_certificate: server_certificate::Certificate =
                    Message::decode(&certificate[..])?;
                match (server_certificate.id, server_certificate.key) {
                    (Some(id), Some(key)) => Ok(Self {
                        key_id: id,
                        key: PublicKey::decode_point(context, &key)?,
                        certificate,
                        signature,
                    }),
                    _ => Err(SealedSessionError::InvalidCertificate),
                }
            }
            _ => Err(SealedSessionError::InvalidCertificate),
        }
    }
}

impl CertificateValidator {
    pub(crate) fn validate(
        &self,
        certificate: &SenderCertificate,
        validation_time: u64,
    ) -> Result<(), SealedSessionError> {
        let server_certificate = &certificate.signer;
        self.trust_root
            .verify_signature(
                &server_certificate.certificate,
                &server_certificate.signature,
            )
            .map_err(|e| {
                error!("failed to verify server certificate: {}", e);
                SealedSessionError::InvalidCertificate
            })?;

        server_certificate
            .key
            .verify_signature(&certificate.certificate, &certificate.signature)
            .map_err(|e| {
                error!("failed to verify certificate: {}", e);
                SealedSessionError::InvalidCertificate
            })?;

        if validation_time > certificate.expiration {
            error!("certificate is expired");
            return Err(SealedSessionError::InvalidCertificate);
        }

        Ok(())
    }
}
