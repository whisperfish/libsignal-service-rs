use std::convert::TryFrom;

use aes::{
    cipher::{NewCipher, StreamCipher},
    Aes256Ctr,
};

use hmac::{Hmac, Mac, NewMac};
use libsignal_protocol::{
    error::SignalProtocolError, message_decrypt_prekey, message_decrypt_signal,
    message_encrypt, CiphertextMessageType, IdentityKeyStore, KeyPair,
    PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, PublicKey,
    SessionStore, SignalMessage, SignedPreKeyStore,
};
use log::error;
use phonenumber::PhoneNumber;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use uuid::Uuid;

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
    ProtocolError(#[from] SignalProtocolError),

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
pub(crate) struct SealedSessionCipher<S, I, SP, P, R> {
    session_store: S,
    identity_key_store: I,
    signed_pre_key_store: SP,
    pre_key_store: P,
    csprng: R,
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
    r#type: CiphertextMessageType,
    sender_certificate: SenderCertificate,
    content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderCertificate {
    signer: ServerCertificate,
    key: PublicKey,
    sender_device_id: u32,
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
    pub device_id: u32,
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

    fn from_bytes(serialized: &[u8]) -> Result<Self, SealedSessionError> {
        let version = serialized[0] >> 4;
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
                ephemeral: PublicKey::deserialize(&ephemeral_public)?,
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
        let mut buf =
            vec![Self::CIPHERTEXT_VERSION << 4 | Self::CIPHERTEXT_VERSION];
        crate::proto::UnidentifiedSenderMessage {
            ephemeral_public: Some(self.ephemeral.serialize().to_vec()),
            encrypted_static: Some(self.encrypted_static),
            encrypted_message: Some(self.encrypted_message),
        }
        .encode(&mut buf)?;
        Ok(buf)
    }
}

impl<S, I, SP, P, R> SealedSessionCipher<S, I, SP, P, R>
where
    S: SessionStore,
    I: IdentityKeyStore,
    SP: SignedPreKeyStore,
    P: PreKeyStore,
    R: Rng + CryptoRng,
{
    pub(crate) fn new(
        session_store: S,
        identity_key_store: I,
        signed_pre_key_store: SP,
        pre_key_store: P,
        csprng: R,
        certificate_validator: CertificateValidator,
    ) -> Self {
        Self {
            session_store,
            identity_key_store,
            signed_pre_key_store,
            pre_key_store,
            csprng,
            certificate_validator,
        }
    }

    /// unused until we make progress on https://github.com/Michael-F-Bryan/libsignal-service-rs/issues/25
    /// messages from unidentified senders can only be sent via a unidentifiedPipe
    #[allow(dead_code)]
    pub async fn encrypt(
        &mut self,
        destination: &ProtocolAddress,
        sender_certificate: SenderCertificate,
        padded_plaintext: &[u8],
    ) -> Result<Vec<u8>, SealedSessionError> {
        let message = message_encrypt(
            padded_plaintext,
            destination,
            &mut self.session_store,
            &mut self.identity_key_store,
            None,
        )
        .await?;

        let our_identity =
            &self.identity_key_store.get_identity_key_pair(None).await?;
        let their_identity = self
            .identity_key_store
            .get_identity(destination, None)
            .await?
            .ok_or(SealedSessionError::NoSessionWithRecipient)?;

        let ephemeral = KeyPair::generate(&mut self.csprng);
        let ephemeral_salt = [
            b"UnidentifiedDelivery",
            their_identity.serialize().as_ref(),
            ephemeral.public_key.serialize().as_ref(),
        ]
        .concat();

        let ephemeral_keys = self.calculate_ephemeral_keys(
            their_identity.public_key(),
            &ephemeral.private_key,
            &ephemeral_salt,
        )?;

        let static_key_ciphertext = self.encrypt_bytes(
            &ephemeral_keys.cipher_key,
            &ephemeral_keys.mac_key,
            &our_identity.public_key().serialize(),
        )?;

        let static_salt = [
            ephemeral_keys.chain_key.as_slice(),
            static_key_ciphertext.as_slice(),
        ]
        .concat();

        let static_keys = self.calculate_static_keys(
            their_identity.public_key(),
            our_identity.private_key(),
            &static_salt,
        )?;

        let content = UnidentifiedSenderMessageContent {
            r#type: message.message_type(),
            sender_certificate,
            content: message.serialize().to_vec(),
        };

        let message_bytes = self.encrypt_bytes(
            &static_keys.cipher_key,
            &static_keys.mac_key,
            &content.into_bytes()?,
        )?;

        UnidentifiedSenderMessage {
            ephemeral: ephemeral.public_key,
            encrypted_static: static_key_ciphertext,
            encrypted_message: message_bytes,
        }
        .into_bytes()
    }

    pub async fn decrypt(
        &mut self,
        ciphertext: &[u8],
        timestamp: u64,
    ) -> Result<DecryptionResult, SealedSessionError> {
        let our_identity =
            self.identity_key_store.get_identity_key_pair(None).await?;

        let wrapper = UnidentifiedSenderMessage::from_bytes(ciphertext)?;

        let ephemeral_salt = [
            b"UnidentifiedDelivery",
            our_identity.public_key().serialize().as_ref(),
            wrapper.ephemeral.serialize().as_ref(),
        ]
        .concat();

        let ephemeral_keys = self.calculate_ephemeral_keys(
            &wrapper.ephemeral,
            our_identity.private_key(),
            &ephemeral_salt,
        )?;

        let static_key_bytes = Self::decrypt_bytes(
            &ephemeral_keys.cipher_key,
            &ephemeral_keys.mac_key,
            &wrapper.encrypted_static,
        )?;

        let static_key = PublicKey::deserialize(&static_key_bytes)?;
        let static_salt =
            [ephemeral_keys.chain_key, wrapper.encrypted_static].concat();
        let static_keys = self.calculate_static_keys(
            &static_key,
            our_identity.private_key(),
            &static_salt,
        )?;

        let message_bytes = Self::decrypt_bytes(
            &static_keys.cipher_key,
            &static_keys.mac_key,
            &wrapper.encrypted_message,
        )?;

        let content = UnidentifiedSenderMessageContent::try_from(
            message_bytes.as_slice(),
        )?;
        self.certificate_validator
            .validate(&content.sender_certificate, timestamp)?;

        self.decrypt_message_content(content).await
    }

    fn calculate_ephemeral_keys(
        &self,
        public_key: &PublicKey,
        private_key: &PrivateKey,
        salt: &[u8],
    ) -> Result<EphemeralKeys, SealedSessionError> {
        let shared_secret = private_key.calculate_agreement(public_key)?;
        let mut ephemeral_derived = [0; 96];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), &shared_secret)
            .expand(&[], &mut ephemeral_derived)
            .expect("valid output length");
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
        let static_secret = private_key.calculate_agreement(public_key)?;
        let mut static_derived = [0; 96];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), &static_secret)
            .expand(&[], &mut static_derived)
            .expect("valid output length");
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
        cipher.apply_keystream(&mut ciphertext);

        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
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

        let mut verifier = Hmac::<Sha256>::new_from_slice(mac_key)
            .map_err(|_| MacError::InvalidKeyLength)?;
        verifier.update(ciphertext_part1);
        let digest = verifier.finalize().into_bytes();
        let our_mac = &digest[..10];

        if our_mac != their_mac {
            return Err(SealedSessionError::InvalidMacError(MacError::BadMac));
        }

        let mut decrypted = ciphertext_part1.to_vec();
        let mut cipher = Aes256Ctr::new(cipher_key.into(), &[0u8; 16].into());
        cipher.apply_keystream(&mut decrypted);

        Ok(decrypted)
    }

    async fn decrypt_message_content(
        &mut self,
        message: UnidentifiedSenderMessageContent,
    ) -> Result<DecryptionResult, SealedSessionError> {
        let UnidentifiedSenderMessageContent {
            r#type,
            content,
            sender_certificate,
        } = message;
        let sender = crate::cipher::get_preferred_protocol_address(
            &self.session_store,
            &sender_certificate.address(),
            sender_certificate.sender_device_id,
        )
        .await?;

        let msg = match r#type {
            CiphertextMessageType::Whisper => {
                let msg = message_decrypt_signal(
                    &SignalMessage::try_from(&content[..])?,
                    &sender,
                    &mut self.session_store,
                    &mut self.identity_key_store,
                    &mut self.csprng,
                    None,
                )
                .await?;
                msg.as_slice().to_vec()
            },
            CiphertextMessageType::PreKey => {
                let msg = message_decrypt_prekey(
                    &PreKeySignalMessage::try_from(&content[..])?,
                    &sender,
                    &mut self.session_store,
                    &mut self.identity_key_store,
                    &mut self.pre_key_store,
                    &mut self.signed_pre_key_store,
                    &mut self.csprng,
                    None,
                )
                .await?;
                msg.as_slice().to_vec()
            },
            _ => unreachable!("unknown message from unidentified sender type"),
        };

        let version = self
            .session_store
            .load_session(&sender, None)
            .await?
            .ok_or_else(|| {
                SignalProtocolError::SessionNotFound(format!("{}", sender))
            })?
            .session_version()?;

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
    fn try_from(serialized: &[u8]) -> Result<Self, SealedSessionError> {
        use crate::proto::unidentified_sender_message::{self, message};

        let message: unidentified_sender_message::Message =
            prost::Message::decode(serialized)?;

        match (message.r#type, message.sender_certificate, message.content) {
            (Some(message_type), Some(sender_certificate), Some(content)) => {
                Ok(Self {
                    r#type: match message::Type::from_i32(message_type) {
                        Some(message::Type::Message) => {
                            CiphertextMessageType::Whisper
                        },
                        Some(message::Type::PrekeyMessage) => {
                            CiphertextMessageType::PreKey
                        },
                        t => {
                            return Err(
                                SealedSessionError::InvalidMetadataMessageError(
                                    format!("Wrong message type ({:?})", t),
                                ),
                            )
                        },
                    },
                    sender_certificate: SenderCertificate::try_from(
                        sender_certificate,
                    )?,
                    content,
                })
            },
            _ => Err(SealedSessionError::InvalidMetadataMessageError(
                "Missing fields".into(),
            )),
        }
    }

    fn into_bytes(self) -> Result<Vec<u8>, SealedSessionError> {
        use crate::proto::unidentified_sender_message::{self, message};
        use prost::Message;

        let data = unidentified_sender_message::Message {
            r#type: Some(match self.r#type {
                CiphertextMessageType::PreKey => message::Type::PrekeyMessage,
                CiphertextMessageType::Whisper => message::Type::Message,
                _ => {
                    return Err(
                        SealedSessionError::InvalidMetadataMessageError(
                            "unknown ciphertext message type".into(),
                        ),
                    )
                },
            } as i32),
            sender_certificate: Some(crate::proto::SenderCertificate {
                certificate: Some(self.sender_certificate.certificate),
                signature: Some(self.sender_certificate.signature),
            }),
            content: Some(self.content),
        }
        .encode_to_vec();

        Ok(data)
    }
}

impl SenderCertificate {
    fn try_from(
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
                            signer: ServerCertificate::try_from(signer)?,
                            key: PublicKey::deserialize(&identity_key)?,
                            sender_e164,
                            sender_uuid,
                            sender_device_id,
                            expiration: expires,
                            certificate,
                            signature,
                        })
                    },
                    _ => Err(SealedSessionError::InvalidCertificate),
                }
            },
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
                        key: PublicKey::deserialize(&key)?,
                        certificate,
                        signature,
                    }),
                    _ => Err(SealedSessionError::InvalidCertificate),
                }
            },
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

        match self.trust_root.verify_signature(
            &server_certificate.certificate,
            &server_certificate.signature,
        ) {
            Err(_) | Ok(false) => {
                return Err(SealedSessionError::InvalidCertificate)
            },
            _ => (),
        };

        match server_certificate
            .key
            .verify_signature(&certificate.certificate, &certificate.signature)
        {
            Err(_) | Ok(false) => {
                return Err(SealedSessionError::InvalidCertificate)
            },
            _ => (),
        }

        if validation_time > certificate.expiration {
            return Err(SealedSessionError::ExpiredCertificate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use libsignal_protocol::{
        process_prekey_bundle, IdentityKeyPair, IdentityKeyStore,
        InMemIdentityKeyStore, InMemPreKeyStore, InMemSessionStore,
        InMemSignedPreKeyStore, KeyPair, PreKeyBundle, PreKeyRecord,
        PreKeyStore, ProtocolAddress, PublicKey, SignedPreKeyRecord,
        SignedPreKeyStore,
    };

    use crate::{provisioning::generate_registration_id, ServiceAddress};

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

    struct Stores {
        identity_key_store: InMemIdentityKeyStore,
        session_store: InMemSessionStore,
        signed_pre_key_store: InMemSignedPreKeyStore,
        pre_key_store: InMemPreKeyStore,
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() -> anyhow::Result<()> {
        let mut csprng = rand::thread_rng();

        let (alice_stores, bob_stores) = create_stores(&mut csprng).await?;

        let trust_root = KeyPair::generate(&mut csprng);
        let certificate_validator =
            CertificateValidator::new(trust_root.public_key);
        let sender_certificate = create_certificate_for(
            &trust_root,
            alice_address(),
            1,
            *alice_stores
                .identity_key_store
                .get_identity_key_pair(None)
                .await?
                .public_key(),
            31337,
            &mut csprng,
        )?;

        let mut alice_cipher = SealedSessionCipher::new(
            alice_stores.session_store,
            alice_stores.identity_key_store,
            alice_stores.signed_pre_key_store,
            alice_stores.pre_key_store,
            csprng,
            certificate_validator.clone(),
        );

        let ciphertext = alice_cipher
            .encrypt(
                &ProtocolAddress::new("+14152222222".into(), 1),
                sender_certificate,
                "smert za smert".as_bytes(),
            )
            .await?;

        let mut bob_cipher = SealedSessionCipher::new(
            bob_stores.session_store,
            bob_stores.identity_key_store,
            bob_stores.signed_pre_key_store,
            bob_stores.pre_key_store,
            csprng,
            certificate_validator,
        );

        let plaintext = bob_cipher.decrypt(&ciphertext, 31335).await?;

        assert_eq!(
            String::from_utf8_lossy(&plaintext.padded_message),
            "smert za smert".to_string()
        );
        assert_eq!(plaintext.sender_uuid, alice_address().uuid);
        assert_eq!(plaintext.sender_e164, alice_address().phonenumber);
        assert_eq!(plaintext.device_id, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_untrusted() -> anyhow::Result<()> {
        let mut csprng = rand::thread_rng();
        let (alice_stores, bob_stores) = create_stores(&mut csprng).await?;

        let trust_root = KeyPair::generate(&mut csprng);
        let certificate_validator =
            CertificateValidator::new(trust_root.public_key);

        let false_trust_root = KeyPair::generate(&mut csprng);
        let false_certificate_validator =
            CertificateValidator::new(false_trust_root.public_key);

        let sender_certificate = create_certificate_for(
            &trust_root,
            alice_address(),
            1,
            *alice_stores
                .identity_key_store
                .get_identity_key_pair(None)
                .await?
                .public_key(),
            31337,
            &mut csprng,
        )?;

        let mut alice_cipher = SealedSessionCipher::new(
            alice_stores.session_store,
            alice_stores.identity_key_store,
            alice_stores.signed_pre_key_store,
            alice_stores.pre_key_store,
            csprng,
            certificate_validator,
        );

        let ciphertext = alice_cipher
            .encrypt(
                &ProtocolAddress::new("+14152222222".into(), 1),
                sender_certificate,
                "и вот я".as_bytes(),
            )
            .await?;

        let mut bob_cipher = SealedSessionCipher::new(
            bob_stores.session_store,
            bob_stores.identity_key_store,
            bob_stores.signed_pre_key_store,
            bob_stores.pre_key_store,
            csprng,
            false_certificate_validator,
        );

        let plaintext = bob_cipher.decrypt(&ciphertext, 31335).await;

        match plaintext {
            Err(SealedSessionError::InvalidCertificate) => Ok(()),
            _ => panic!("decryption succeeded, this should not happen here!1!"),
        }
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_expired() -> anyhow::Result<()> {
        let mut csprng = rand::thread_rng();
        let (alice_stores, bob_stores) = create_stores(&mut csprng).await?;

        let trust_root = KeyPair::generate(&mut csprng);
        let certificate_validator =
            CertificateValidator::new(trust_root.public_key);
        let sender_certificate = create_certificate_for(
            &trust_root,
            alice_address(),
            1,
            *alice_stores
                .identity_key_store
                .get_identity_key_pair(None)
                .await?
                .public_key(),
            31337,
            &mut csprng,
        )?;

        let mut alice_cipher = SealedSessionCipher::new(
            alice_stores.session_store,
            alice_stores.identity_key_store,
            alice_stores.signed_pre_key_store,
            alice_stores.pre_key_store,
            csprng,
            certificate_validator.clone(),
        );

        let ciphertext = alice_cipher
            .encrypt(
                &ProtocolAddress::new("+14152222222".into(), 1),
                sender_certificate,
                "smert za smert".as_bytes(),
            )
            .await?;

        let mut bob_cipher = SealedSessionCipher::new(
            bob_stores.session_store,
            bob_stores.identity_key_store,
            bob_stores.signed_pre_key_store,
            bob_stores.pre_key_store,
            csprng,
            certificate_validator,
        );

        match bob_cipher.decrypt(&ciphertext, 31338).await {
            Err(SealedSessionError::ExpiredCertificate) => Ok(()),
            _ => panic!("certificate is expired, we should not get decrypted data here!11!")
        }
    }

    #[tokio::test]
    async fn test_encrypt_from_wrong_identity() -> anyhow::Result<()> {
        let mut csprng = rand::thread_rng();
        let (alice_stores, bob_stores) = create_stores(&mut csprng).await?;

        let trust_root = KeyPair::generate(&mut csprng);
        let random_key_pair = KeyPair::generate(&mut csprng);
        let certificate_validator =
            CertificateValidator::new(trust_root.public_key);
        let sender_certificate = create_certificate_for(
            &random_key_pair,
            alice_address(),
            1,
            *alice_stores
                .identity_key_store
                .get_identity_key_pair(None)
                .await?
                .public_key(),
            31337,
            &mut csprng,
        )?;

        let mut alice_cipher = SealedSessionCipher::new(
            alice_stores.session_store,
            alice_stores.identity_key_store,
            alice_stores.signed_pre_key_store,
            alice_stores.pre_key_store,
            csprng,
            certificate_validator.clone(),
        );

        let ciphertext = alice_cipher
            .encrypt(
                &ProtocolAddress::new("+14152222222".into(), 1),
                sender_certificate,
                "smert za smert".as_bytes(),
            )
            .await?;

        let mut bob_cipher = SealedSessionCipher::new(
            bob_stores.session_store,
            bob_stores.identity_key_store,
            bob_stores.signed_pre_key_store,
            bob_stores.pre_key_store,
            csprng,
            certificate_validator,
        );

        match bob_cipher.decrypt(&ciphertext, 31335).await {
            Err(SealedSessionError::InvalidCertificate) => Ok(()),
            _ => panic!("the certificate is invalid here!11"),
        }
    }

    async fn create_stores<R: rand::Rng + rand::CryptoRng>(
        csprng: &mut R,
    ) -> anyhow::Result<(Stores, Stores)> {
        let mut alice_stores = Stores {
            identity_key_store: InMemIdentityKeyStore::new(
                IdentityKeyPair::generate(csprng),
                generate_registration_id(csprng),
            ),
            session_store: InMemSessionStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
        };

        let mut bob_stores = Stores {
            identity_key_store: InMemIdentityKeyStore::new(
                IdentityKeyPair::generate(csprng),
                generate_registration_id(csprng),
            ),
            session_store: InMemSessionStore::new(),
            signed_pre_key_store: InMemSignedPreKeyStore::new(),
            pre_key_store: InMemPreKeyStore::new(),
        };

        initialize_session(&mut alice_stores, &mut bob_stores, csprng).await?;

        Ok((alice_stores, bob_stores))
    }

    fn create_certificate_for<R: rand::Rng + rand::CryptoRng>(
        trust_root: &KeyPair,
        addr: ServiceAddress,
        device_id: u32,
        identity_key: PublicKey,
        expires: u64,
        csprng: &mut R,
    ) -> Result<SenderCertificate, SealedSessionError> {
        let server_key = KeyPair::generate(csprng);

        let uuid = addr.uuid.as_ref().map(uuid::Uuid::to_string);
        let e164 = addr.e164();

        let server_certificate_bytes =
            crate::proto::server_certificate::Certificate {
                id: Some(1),
                key: Some(server_key.public_key.serialize().into_vec()),
            }
            .encode_to_vec();

        let server_certificate_signature = trust_root
            .private_key
            .calculate_signature(&server_certificate_bytes, csprng)?;

        let server_certificate = crate::proto::ServerCertificate {
            certificate: Some(server_certificate_bytes),
            signature: Some(server_certificate_signature.into_vec()),
        };

        let sender_certificate_bytes =
            crate::proto::sender_certificate::Certificate {
                sender_uuid: uuid,
                sender_e164: e164,
                sender_device: Some(device_id),
                identity_key: Some(identity_key.serialize().into_vec()),
                expires: Some(expires),
                signer: Some(server_certificate),
            }
            .encode_to_vec();

        let sender_certificate_signature = server_key
            .private_key
            .calculate_signature(&sender_certificate_bytes, csprng)?;

        SenderCertificate::try_from(crate::proto::SenderCertificate {
            certificate: Some(sender_certificate_bytes),
            signature: Some(sender_certificate_signature.into_vec()),
        })
    }

    async fn initialize_session<R: rand::Rng + rand::CryptoRng>(
        alice_stores: &mut Stores,
        bob_stores: &mut Stores,
        csprng: &mut R,
    ) -> Result<(), SealedSessionError> {
        let bob_pre_key = PreKeyRecord::new(1, &KeyPair::generate(csprng));
        let bob_identity_key_pair = bob_stores
            .identity_key_store
            .get_identity_key_pair(None)
            .await?;

        // TODO: check
        let signed_pre_key_pair = KeyPair::generate(csprng);
        let signed_pre_key_signature = bob_identity_key_pair
            .private_key()
            .calculate_signature(
                &signed_pre_key_pair.public_key.serialize(),
                csprng,
            )?
            .into_vec();

        let bob_signed_pre_key_record = SignedPreKeyRecord::new(
            2,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            &signed_pre_key_pair,
            &signed_pre_key_signature,
        );

        let bob_bundle = PreKeyBundle::new(
            1,
            1,
            Some((1, bob_pre_key.public_key()?)),
            2,
            signed_pre_key_pair.public_key,
            signed_pre_key_signature,
            *bob_identity_key_pair.identity_key(),
        )?;

        process_prekey_bundle(
            &ProtocolAddress::new("+14152222222".into(), 1),
            &mut alice_stores.session_store,
            &mut alice_stores.identity_key_store,
            &bob_bundle,
            csprng,
            None,
        )
        .await?;

        bob_stores
            .signed_pre_key_store
            .save_signed_pre_key(2, &bob_signed_pre_key_record, None)
            .await?;
        bob_stores
            .pre_key_store
            .save_pre_key(1, &bob_pre_key, None)
            .await?;
        Ok(())
    }
}
