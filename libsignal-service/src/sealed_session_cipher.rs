use phonenumber::PhoneNumber;
use uuid::Uuid;

use aes_ctr::{
    cipher::stream::{NewStreamCipher, StreamCipher},
    Aes256Ctr,
};

use hmac::{Hmac, Mac, NewMac};
use libsignal_protocol::{
    keys::{PrivateKey, PublicKey},
    messages::{CiphertextType, PreKeySignalMessage, SignalMessage},
    Address as ProtocolAddress, Context, Deserializable, Serializable,
    SessionCipher, StoreContext,
};
use log::error;
use sha2::Sha256;

use crate::{push_service::ProfileKey, ServiceAddress};

#[derive(Debug, thiserror::Error)]
pub enum SealedSessionError {
    #[error("Unknown version {0}")]
    InvalidMetadataVersionError(u8),

    #[error("{0}")]
    InvalidMetadataMessageError(String),

    #[error("Invalid MAC: {0}")]
    InvalidMacError(#[from] MacError),

    #[error("Invalid certificate")]
    InvalidCertificate,

    #[error("Expired certificate")]
    ExpiredCertificate,

    #[error("Failed to decode protobuf {0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Failed to encode protobuf: {0}")]
    EncodeError(#[from] prost::EncodeError),

    #[error("Protocol error {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),

    #[error("recipient not trusted")]
    NoSessionWithRecipient,

    #[error("Supplied phone number could not be parsed in E164 format")]
    InvalidPhoneNumber(#[from] phonenumber::ParseError),

    #[error("Supplied uuid could not be parsed")]
    InvalidUuidError(#[from] uuid::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum MacError {
    #[error("Invalid MAC key length")]
    InvalidKeyLength,
    #[error("Ciphertext not long enough ({0} bytes) for MAC")]
    CiphertextNotLongEnough(usize),
    #[error("Bad MAC")]
    BadMac,
}

#[derive(Clone)]
pub(crate) struct SealedSessionCipher {
    context: Context,
    store_context: StoreContext,
    local_address: ServiceAddress,
    certificate_validator: CertificateValidator,
}

#[derive(Clone)]
pub struct UnidentifiedAccessPair {
    target_unidentified_access: UnidentifiedAccess,
    self_unidentified_access: UnidentifiedAccess,
}

#[derive(Clone)]
pub struct UnidentifiedAccess {
    access_key: Vec<u8>,
    sender_certificate: SenderCertificate,
}

#[derive(Debug, Clone)]
struct UnidentifiedSenderMessage {
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
    sender_uuid: Option<uuid::Uuid>,
    sender_e164: Option<phonenumber::PhoneNumber>,
    expiration: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerCertificate {
    key_id: u32,
    key: PublicKey,
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
    trust_root: PublicKey,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct DecryptionResult {
    pub sender_uuid: Option<Uuid>,
    pub sender_e164: Option<PhoneNumber>,
    pub device_id: i32,
    pub padded_message: Vec<u8>,
    pub version: u32,
}

impl UnidentifiedAccess {
    pub fn new(
        profile_key: &ProfileKey,
        sender_certificate: SenderCertificate,
    ) -> Result<Self, SealedSessionError> {
        Ok(UnidentifiedAccess {
            access_key: profile_key.derive_access_key(),
            sender_certificate,
        })
    }
}

impl UnidentifiedSenderMessage {
    const CIPHERTEXT_VERSION: u8 = 1;

    fn from_bytes(
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

    fn into_bytes(self) -> Result<Vec<u8>, SealedSessionError> {
        use prost::Message;
        let mut buf = vec![];
        buf.push(
            (Self::CIPHERTEXT_VERSION << 4 | Self::CIPHERTEXT_VERSION) & 0xFF,
        );
        crate::proto::UnidentifiedSenderMessage {
            ephemeral_public: Some(
                self.ephemeral.to_bytes()?.as_slice().to_vec(),
            ),
            encrypted_static: Some(self.encrypted_static),
            encrypted_message: Some(self.encrypted_message),
        }
        .encode(&mut buf)?;
        Ok(buf)
    }
}

impl SealedSessionCipher {
    pub(crate) fn new(
        context: Context,
        store_context: StoreContext,
        local_address: ServiceAddress,
        certificate_validator: CertificateValidator,
    ) -> Self {
        Self {
            context,
            store_context,
            local_address,
            certificate_validator,
        }
    }

    /// unused until we make progress on https://github.com/Michael-F-Bryan/libsignal-service-rs/issues/25
    /// messages from unidentified senders can only be sent via a unidentifiedPipe
    #[allow(dead_code)]
    pub fn encrypt(
        &self,
        destination: &ProtocolAddress,
        sender_certificate: SenderCertificate,
        padded_plaintext: &[u8],
    ) -> Result<Vec<u8>, SealedSessionError> {
        let message = SessionCipher::new(
            &self.context,
            &self.store_context,
            &destination,
        )?
        .encrypt(padded_plaintext)?;

        let our_identity = &self.store_context.identity_key_pair()?;
        let their_identity = self
            .store_context
            .get_identity(destination.clone())?
            .ok_or(SealedSessionError::NoSessionWithRecipient)?;

        let ephemeral = libsignal_protocol::generate_key_pair(&self.context)?;
        let ephemeral_salt = [
            b"UnidentifiedDelivery",
            their_identity.to_bytes()?.as_slice(),
            ephemeral.public().to_bytes()?.as_slice(),
        ]
        .concat();

        let ephemeral_keys = self.calculate_ephemeral_keys(
            &their_identity,
            &ephemeral.private(),
            &ephemeral_salt,
        )?;

        let static_key_ciphertext = self.encrypt_bytes(
            &ephemeral_keys.cipher_key,
            &ephemeral_keys.mac_key,
            our_identity.public().to_bytes()?.as_slice(),
        )?;

        let static_salt = [
            ephemeral_keys.chain_key.as_slice(),
            static_key_ciphertext.as_slice(),
        ]
        .concat();

        let static_keys = self.calculate_static_keys(
            &their_identity,
            &our_identity.private(),
            &static_salt,
        )?;

        let content = UnidentifiedSenderMessageContent {
            r#type: message.get_type()?,
            sender_certificate,
            content: message.serialize()?.as_slice().to_vec(),
        };

        let message_bytes = self.encrypt_bytes(
            &static_keys.cipher_key,
            &static_keys.mac_key,
            &content.into_bytes()?,
        )?;

        Ok(UnidentifiedSenderMessage {
            ephemeral: ephemeral.public(),
            encrypted_static: static_key_ciphertext,
            encrypted_message: message_bytes,
        }
        .into_bytes()?)
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        timestamp: u64,
    ) -> Result<DecryptionResult, SealedSessionError> {
        let our_identity = self.store_context.identity_key_pair()?;
        let wrapper =
            UnidentifiedSenderMessage::from_bytes(&self.context, ciphertext)?;

        let ephemeral_salt = [
            b"UnidentifiedDelivery",
            our_identity.public().to_bytes()?.as_slice(),
            wrapper.ephemeral.to_bytes()?.as_slice(),
        ]
        .concat();

        let ephemeral_keys = self.calculate_ephemeral_keys(
            &wrapper.ephemeral,
            &our_identity.private(),
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
            &our_identity.private(),
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

        self.decrypt_message_content(content)
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
        let ephemeral_keys = EphemeralKeys {
            chain_key: ephemeral_derived[0..32].into(),
            cipher_key: ephemeral_derived[32..64].into(),
            mac_key: ephemeral_derived[64..96].into(),
        };
        Ok(ephemeral_keys)
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

    fn encrypt_bytes(
        &self,
        cipher_key: &[u8],
        mac_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SealedSessionError> {
        let mut cipher = Aes256Ctr::new(cipher_key.into(), &[0u8; 16].into());

        let mut ciphertext = plaintext.to_vec();
        cipher.encrypt(&mut ciphertext);

        let mut mac = Hmac::<Sha256>::new_varkey(&mac_key)
            .map_err(|_| MacError::InvalidKeyLength)?;
        mac.update(&ciphertext);
        let our_mac = mac.finalize().into_bytes();

        let encrypted = [ciphertext.as_slice(), &our_mac[..10]].concat();

        Ok(encrypted)
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
            .map_err(|_| MacError::InvalidKeyLength)?;
        verifier.update(&ciphertext_part1);
        let digest = verifier.finalize().into_bytes();
        let our_mac = &digest[..10];

        if our_mac != their_mac {
            return Err(SealedSessionError::InvalidMacError(MacError::BadMac));
        }

        let mut decrypted = ciphertext_part1.to_vec();
        let mut cipher = Aes256Ctr::new(cipher_key.into(), &[0u8; 16].into());
        cipher.decrypt(&mut decrypted);

        Ok(decrypted)
    }

    fn decrypt_message_content(
        &self,
        message: UnidentifiedSenderMessageContent,
    ) -> Result<DecryptionResult, SealedSessionError> {
        let UnidentifiedSenderMessageContent {
            r#type,
            content,
            sender_certificate,
        } = message;
        let sender = crate::cipher::get_preferred_protocol_address(
            &self.store_context,
            sender_certificate.address(),
            sender_certificate.sender_device_id,
        )?;
        let session_cipher =
            SessionCipher::new(&self.context, &self.store_context, &sender)?;
        let msg = match r#type {
            CiphertextType::Signal => {
                let msg = session_cipher.decrypt_message(
                    &SignalMessage::deserialize(&self.context, &content)?,
                )?;
                msg.as_slice().to_vec()
            }
            CiphertextType::PreKey => {
                let msg = session_cipher.decrypt_pre_key_message(
                    &PreKeySignalMessage::deserialize(&self.context, &content)?,
                )?;
                msg.as_slice().to_vec()
            }
            _ => unreachable!("unknown message from unidentified sender type"),
        };

        let version = session_cipher.get_session_version()?;
        Ok(DecryptionResult {
            padded_message: msg,
            version,
            sender_uuid: sender_certificate.sender_uuid,
            sender_e164: sender_certificate.sender_e164,
            device_id: sender_certificate.sender_device_id,
        })
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
                        t => {
                            return Err(
                                SealedSessionError::InvalidMetadataMessageError(
                                    format!("Wrong message type ({:?})", t),
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

    fn into_bytes(self) -> Result<Vec<u8>, SealedSessionError> {
        use crate::proto::unidentified_sender_message::{self, message};
        use prost::Message;
        let mut data = vec![];

        unidentified_sender_message::Message {
            r#type: Some(match self.r#type {
                CiphertextType::PreKey => message::Type::PrekeyMessage,
                CiphertextType::Signal => message::Type::Message,
                _ => {
                    return Err(
                        SealedSessionError::InvalidMetadataMessageError(
                            "unknown ciphertext message type".into(),
                        ),
                    )
                }
            } as i32),
            sender_certificate: Some(crate::proto::SenderCertificate {
                certificate: Some(self.sender_certificate.certificate),
                signature: Some(self.sender_certificate.signature),
            }),
            content: Some(self.content),
        }
        .encode(&mut data)?;

        Ok(data)
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

                        let sender_e164 = sender_e164
                            .map(|s| phonenumber::parse(None, s))
                            .transpose()?;
                        let sender_uuid = sender_uuid
                            .as_deref()
                            .map(Uuid::parse_str)
                            .transpose()?;

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

    fn address(&self) -> ServiceAddress {
        ServiceAddress {
            uuid: self.sender_uuid,
            phonenumber: self.sender_e164.clone(),
            relay: None,
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
    pub fn new(trust_root: PublicKey) -> Self {
        Self { trust_root }
    }

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
            return Err(SealedSessionError::ExpiredCertificate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use libsignal_protocol::{
        self as sig,
        crypto::DefaultCrypto,
        keys::PreKey,
        keys::{KeyPair, PublicKey},
        stores::InMemoryPreKeyStore,
        stores::InMemorySessionStore,
        stores::{InMemoryIdentityKeyStore, InMemorySignedPreKeyStore},
        Address as ProtocolAddress, Context, PreKeyBundle, Serializable,
        SessionBuilder, StoreContext,
    };

    use crate::ServiceAddress;

    use super::{
        CertificateValidator, SealedSessionCipher, SealedSessionError,
        SenderCertificate,
    };

    use prost::Message;

    fn alice_address() -> ServiceAddress {
        ServiceAddress::parse(
            Some("+14151111111"),
            Some("9d0652a3-dcc3-4d11-975f-74d61598733f"),
        )
        .unwrap()
    }

    fn bob_address() -> ServiceAddress {
        ServiceAddress::parse(
            Some("+14152222222"),
            Some("e80f7bbe-5b94-471e-bd8c-2173654ea3d1"),
        )
        .unwrap()
    }

    #[test]
    fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let (ctx, alice_store_context, bob_store_context) = create_contexts()?;
        initialize_session(&ctx, &bob_store_context, &alice_store_context)?;

        let trust_root = libsignal_protocol::generate_key_pair(&ctx)?;
        let certificate_validator =
            CertificateValidator::new(trust_root.public());
        let sender_certificate = create_certificate_for(
            &ctx,
            &trust_root,
            alice_address(),
            1,
            alice_store_context.identity_key_pair()?.public(),
            31337,
        )?;

        let alice_cipher = SealedSessionCipher::new(
            ctx.clone(),
            alice_store_context,
            alice_address(),
            certificate_validator.clone(),
        );
        let ciphertext = alice_cipher.encrypt(
            &ProtocolAddress::new("+14152222222", 1),
            sender_certificate,
            "smert za smert".as_bytes(),
        )?;

        let bob_cipher = SealedSessionCipher::new(
            ctx.clone(),
            bob_store_context,
            bob_address(),
            certificate_validator,
        );

        let plaintext = bob_cipher.decrypt(&ciphertext, 31335)?;

        assert_eq!(
            String::from_utf8_lossy(&plaintext.padded_message),
            "smert za smert".to_string()
        );
        assert_eq!(plaintext.sender_uuid, alice_address().uuid);
        assert_eq!(plaintext.sender_e164, alice_address().phonenumber);
        assert_eq!(plaintext.device_id, 1);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_untrusted() -> anyhow::Result<()> {
        let (ctx, alice_store_context, bob_store_context) = create_contexts()?;
        initialize_session(&ctx, &bob_store_context, &alice_store_context)?;

        let trust_root = libsignal_protocol::generate_key_pair(&ctx)?;
        let certificate_validator =
            CertificateValidator::new(trust_root.public());

        let false_trust_root = libsignal_protocol::generate_key_pair(&ctx)?;
        let false_certificate_validator =
            CertificateValidator::new(false_trust_root.public());

        let sender_certificate = create_certificate_for(
            &ctx,
            &trust_root,
            alice_address(),
            1,
            alice_store_context.identity_key_pair()?.public(),
            31337,
        )?;

        let alice_cipher = SealedSessionCipher::new(
            ctx.clone(),
            alice_store_context,
            alice_address(),
            certificate_validator,
        );

        let ciphertext = alice_cipher.encrypt(
            &ProtocolAddress::new("+14152222222", 1),
            sender_certificate,
            "и вот я".as_bytes(),
        )?;

        let bob_cipher = SealedSessionCipher::new(
            ctx,
            bob_store_context,
            bob_address(),
            false_certificate_validator,
        );

        let plaintext = bob_cipher.decrypt(&ciphertext, 31335);

        match plaintext {
            Err(SealedSessionError::InvalidCertificate) => Ok(()),
            _ => panic!("decryption succeeded, this should not happen here!1!"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_expired() -> anyhow::Result<()> {
        let (ctx, alice_store_context, bob_store_context) = create_contexts()?;
        initialize_session(&ctx, &bob_store_context, &alice_store_context)?;

        let trust_root = libsignal_protocol::generate_key_pair(&ctx)?;
        let certificate_validator =
            CertificateValidator::new(trust_root.public());
        let sender_certificate = create_certificate_for(
            &ctx,
            &trust_root,
            alice_address(),
            1,
            alice_store_context.identity_key_pair()?.public(),
            31337,
        )?;

        let alice_cipher = SealedSessionCipher::new(
            ctx.clone(),
            alice_store_context,
            alice_address(),
            certificate_validator.clone(),
        );

        let ciphertext = alice_cipher.encrypt(
            &ProtocolAddress::new("+14152222222", 1),
            sender_certificate,
            "smert za smert".as_bytes(),
        )?;

        let bob_cipher = SealedSessionCipher::new(
            ctx.clone(),
            bob_store_context,
            bob_address(),
            certificate_validator,
        );

        match bob_cipher.decrypt(&ciphertext, 31338) {
            Err(SealedSessionError::ExpiredCertificate) => Ok(()),
            _ => panic!("certificate is expired, we should not get decrypted data here!11!")
        }
    }

    #[test]
    fn test_encrypt_from_wrong_identity() -> anyhow::Result<()> {
        let (ctx, alice_store_context, bob_store_context) = create_contexts()?;
        initialize_session(&ctx, &bob_store_context, &alice_store_context)?;

        let trust_root = libsignal_protocol::generate_key_pair(&ctx)?;
        let random_key_pair = libsignal_protocol::generate_key_pair(&ctx)?;
        let certificate_validator =
            CertificateValidator::new(trust_root.public());
        let sender_certificate = create_certificate_for(
            &ctx,
            &random_key_pair,
            alice_address(),
            1,
            alice_store_context.identity_key_pair()?.public(),
            31337,
        )?;

        let alice_cipher = SealedSessionCipher::new(
            ctx.clone(),
            alice_store_context,
            alice_address(),
            certificate_validator.clone(),
        );
        let ciphertext = alice_cipher.encrypt(
            &ProtocolAddress::new("+14152222222", 1),
            sender_certificate,
            "smert za smert".as_bytes(),
        )?;

        let bob_cipher = SealedSessionCipher::new(
            ctx.clone(),
            bob_store_context,
            bob_address(),
            certificate_validator,
        );

        match bob_cipher.decrypt(&ciphertext, 31335) {
            Err(SealedSessionError::InvalidCertificate) => Ok(()),
            _ => panic!("the certificate is invalid here!11"),
        }
    }

    fn create_contexts(
    ) -> Result<(Context, StoreContext, StoreContext), SealedSessionError> {
        let ctx = Context::new(DefaultCrypto::default())?;

        let alice_identity = sig::generate_identity_key_pair(&ctx).unwrap();
        let alice_store = sig::store_context(
            &ctx,
            InMemoryPreKeyStore::default(),
            InMemorySignedPreKeyStore::default(),
            InMemorySessionStore::default(),
            InMemoryIdentityKeyStore::new(
                sig::generate_registration_id(&ctx, 0).unwrap(),
                &alice_identity,
            ),
        )?;

        let bob_identity = sig::generate_identity_key_pair(&ctx).unwrap();
        let bob_store = sig::store_context(
            &ctx,
            InMemoryPreKeyStore::default(),
            InMemorySignedPreKeyStore::default(),
            InMemorySessionStore::default(),
            InMemoryIdentityKeyStore::new(
                sig::generate_registration_id(&ctx, 0).unwrap(),
                &bob_identity,
            ),
        )?;

        Ok((ctx, alice_store, bob_store))
    }

    fn create_certificate_for(
        context: &Context,
        trust_root: &KeyPair,
        addr: ServiceAddress,
        device_id: u32,
        identity_key: PublicKey,
        expires: u64,
    ) -> Result<SenderCertificate, SealedSessionError> {
        let server_key = libsignal_protocol::generate_key_pair(&context)?;

        let uuid = addr.uuid.as_ref().map(uuid::Uuid::to_string);
        let e164 = addr.e164();

        let mut server_certificate_bytes = vec![];
        crate::proto::server_certificate::Certificate {
            id: Some(1),
            key: Some(server_key.public().serialize()?.as_slice().to_vec()),
        }
        .encode(&mut server_certificate_bytes)?;

        let server_certificate_signature =
            libsignal_protocol::calculate_signature(
                &context,
                &trust_root.private(),
                &server_certificate_bytes,
            )?
            .as_slice()
            .to_vec();

        let server_certificate = crate::proto::ServerCertificate {
            certificate: Some(server_certificate_bytes),
            signature: Some(server_certificate_signature),
        };

        let mut sender_certificate_bytes = vec![];
        crate::proto::sender_certificate::Certificate {
            sender_uuid: uuid,
            sender_e164: e164,
            sender_device: Some(device_id),
            identity_key: Some(identity_key.serialize()?.as_slice().to_vec()),
            expires: Some(expires),
            signer: Some(server_certificate),
        }
        .encode(&mut sender_certificate_bytes)?;

        let sender_certificate_signature =
            libsignal_protocol::calculate_signature(
                &context,
                &server_key.private(),
                &sender_certificate_bytes,
            )?
            .as_slice()
            .to_vec();

        Ok(SenderCertificate::try_from(
            &context,
            crate::proto::SenderCertificate {
                certificate: Some(sender_certificate_bytes),
                signature: Some(sender_certificate_signature),
            },
        )?)
    }

    fn initialize_session(
        context: &Context,
        bob_store_context: &StoreContext,
        alice_store_context: &StoreContext,
    ) -> Result<(), SealedSessionError> {
        let bob_pre_key = libsignal_protocol::generate_key_pair(&context)?;
        let bob_identity_key = bob_store_context.identity_key_pair()?;
        let bob_signed_pre_key = libsignal_protocol::generate_signed_pre_key(
            &context,
            &bob_identity_key,
            2,
            UNIX_EPOCH,
        )?;

        let bob_bundle = PreKeyBundle::builder()
            .registration_id(1)
            .device_id(1)
            .pre_key(1, &bob_pre_key.public())
            .signed_pre_key(2, &bob_signed_pre_key.key_pair().public())
            .signature(&bob_signed_pre_key.signature())
            .identity_key(&bob_identity_key.public())
            .build()?;

        let alice_session_builder = SessionBuilder::new(
            &context,
            &alice_store_context,
            &ProtocolAddress::new("+14152222222", 1),
        );
        alice_session_builder.process_pre_key_bundle(&bob_bundle)?;

        bob_store_context.store_signed_pre_key(&bob_signed_pre_key)?;
        bob_store_context.store_pre_key(&PreKey::new(1, &bob_pre_key)?)?;
        Ok(())
    }
}
