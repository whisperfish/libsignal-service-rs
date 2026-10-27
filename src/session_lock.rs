//! One session step at a time.

use std::{fmt, sync::Arc};

use tokio::sync::{Mutex, MutexGuard};

/// Runs session steps (load a session, ratchet it, store it) one at a time.
///
/// Two steps on one session at once start from the same state: two messages go
/// out with one counter, and the recipient drops the second as a duplicate.
/// Give an account's [`ServiceCipher`](crate::cipher::ServiceCipher)s and
/// [`MessageSender`](crate::sender::MessageSender)s one lock, as
/// Signal-Android does with its [`SignalSessionLock`]. Steps never wait on the
/// network.
///
/// [`SignalSessionLock`]: https://github.com/signalapp/Signal-Android/blob/main/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalSessionLock.java
#[derive(Clone, Default)]
pub struct SessionLock(Arc<Mutex<()>>);

impl SessionLock {
    /// Waits for the steps before, in the order they asked; this one lasts as
    /// long as the guard.
    pub async fn step(&self) -> MutexGuard<'_, ()> {
        self.0.lock().await
    }
}

impl fmt::Debug for SessionLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionLock").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use async_trait::async_trait;
    use base64::Engine;
    use futures::FutureExt;
    use libsignal_core::DeviceId;
    use libsignal_protocol::{
        kem, message_decrypt, process_prekey_bundle, CiphertextMessage,
        Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
        IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
        PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
        ProtocolAddress, ProtocolStore, PublicKey, SenderKeyRecord,
        SenderKeyStore, ServiceId, SessionRecord, SessionStore,
        SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
        SignedPreKeyStore, Timestamp,
    };
    use rand::rng;
    use uuid::Uuid;

    use super::SessionLock;
    use crate::{
        cipher::ServiceCipher, session_store::SessionStoreExt,
        utils::BASE64_RELAXED,
    };

    type Result<T> = std::result::Result<T, SignalProtocolError>;

    /// An in-memory store that, like one on disk, lets other tasks run while it
    /// loads a session.
    #[derive(Clone)]
    struct Yielding(Rc<RefCell<InMemSignalProtocolStore>>);

    /// Runs one of the in-memory store's methods, which never wait.
    macro_rules! now {
        ($call:expr) => {
            $call
                .now_or_never()
                .expect("the in-memory store never waits")
        };
    }

    #[async_trait(?Send)]
    impl SessionStore for Yielding {
        async fn load_session(
            &self,
            address: &ProtocolAddress,
        ) -> Result<Option<SessionRecord>> {
            let session = now!(self.0.borrow().load_session(address));
            tokio::task::yield_now().await;
            session
        }

        async fn store_session(
            &mut self,
            address: &ProtocolAddress,
            record: &SessionRecord,
        ) -> Result<()> {
            now!(self.0.borrow_mut().store_session(address, record))
        }
    }

    #[async_trait(?Send)]
    impl SessionStoreExt for Yielding {
        async fn get_sub_device_sessions(
            &self,
            _: &ServiceId,
        ) -> Result<Vec<DeviceId>> {
            Ok(vec![])
        }

        async fn delete_session(&self, _: &ProtocolAddress) -> Result<()> {
            unimplemented!("not deleted in these tests")
        }

        async fn delete_all_sessions(&self, _: &ServiceId) -> Result<usize> {
            unimplemented!("not deleted in these tests")
        }
    }

    #[async_trait(?Send)]
    impl IdentityKeyStore for Yielding {
        async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
            now!(self.0.borrow().get_identity_key_pair())
        }

        async fn get_local_registration_id(&self) -> Result<u32> {
            now!(self.0.borrow().get_local_registration_id())
        }

        async fn save_identity(
            &mut self,
            address: &ProtocolAddress,
            identity: &IdentityKey,
        ) -> Result<IdentityChange> {
            now!(self.0.borrow_mut().save_identity(address, identity))
        }

        async fn is_trusted_identity(
            &self,
            address: &ProtocolAddress,
            identity: &IdentityKey,
            direction: Direction,
        ) -> Result<bool> {
            now!(self
                .0
                .borrow()
                .is_trusted_identity(address, identity, direction))
        }

        async fn get_identity(
            &self,
            address: &ProtocolAddress,
        ) -> Result<Option<IdentityKey>> {
            now!(self.0.borrow().get_identity(address))
        }
    }

    #[async_trait(?Send)]
    impl PreKeyStore for Yielding {
        async fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord> {
            now!(self.0.borrow().get_pre_key(id))
        }

        async fn save_pre_key(
            &mut self,
            id: PreKeyId,
            record: &PreKeyRecord,
        ) -> Result<()> {
            now!(self.0.borrow_mut().save_pre_key(id, record))
        }

        async fn remove_pre_key(&mut self, id: PreKeyId) -> Result<()> {
            now!(self.0.borrow_mut().remove_pre_key(id))
        }
    }

    #[async_trait(?Send)]
    impl SignedPreKeyStore for Yielding {
        async fn get_signed_pre_key(
            &self,
            id: SignedPreKeyId,
        ) -> Result<SignedPreKeyRecord> {
            now!(self.0.borrow().get_signed_pre_key(id))
        }

        async fn save_signed_pre_key(
            &mut self,
            id: SignedPreKeyId,
            record: &SignedPreKeyRecord,
        ) -> Result<()> {
            now!(self.0.borrow_mut().save_signed_pre_key(id, record))
        }
    }

    #[async_trait(?Send)]
    impl KyberPreKeyStore for Yielding {
        async fn get_kyber_pre_key(
            &self,
            id: KyberPreKeyId,
        ) -> Result<KyberPreKeyRecord> {
            now!(self.0.borrow().get_kyber_pre_key(id))
        }

        async fn save_kyber_pre_key(
            &mut self,
            id: KyberPreKeyId,
            record: &KyberPreKeyRecord,
        ) -> Result<()> {
            now!(self.0.borrow_mut().save_kyber_pre_key(id, record))
        }

        async fn mark_kyber_pre_key_used(
            &mut self,
            id: KyberPreKeyId,
            ec_id: SignedPreKeyId,
            base_key: &PublicKey,
        ) -> Result<()> {
            now!(self
                .0
                .borrow_mut()
                .mark_kyber_pre_key_used(id, ec_id, base_key))
        }
    }

    #[async_trait(?Send)]
    impl SenderKeyStore for Yielding {
        async fn store_sender_key(
            &mut self,
            sender: &ProtocolAddress,
            distribution_id: Uuid,
            record: &SenderKeyRecord,
        ) -> Result<()> {
            now!(self.0.borrow_mut().store_sender_key(
                sender,
                distribution_id,
                record
            ))
        }

        async fn load_sender_key(
            &mut self,
            sender: &ProtocolAddress,
            distribution_id: Uuid,
        ) -> Result<Option<SenderKeyRecord>> {
            now!(self.0.borrow_mut().load_sender_key(sender, distribution_id))
        }
    }

    impl ProtocolStore for Yielding {}

    fn address(n: u128) -> ProtocolAddress {
        ProtocolAddress::new(
            Uuid::from_u128(n).to_string(),
            DeviceId::new(1).unwrap(),
        )
    }

    /// Bob, with a signed and a Kyber pre-key, and the bundle that starts a
    /// session with him.
    fn bob() -> (InMemSignalProtocolStore, PreKeyBundle) {
        let mut rng = rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let mut store = InMemSignalProtocolStore::new(identity, 2).unwrap();
        let signed = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), &mut rng)
            .unwrap();
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let kyber_signature = identity
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), &mut rng)
            .unwrap();
        now!(store.save_signed_pre_key(
            1.into(),
            &SignedPreKeyRecord::new(
                1.into(),
                Timestamp::from_epoch_millis(1),
                &signed,
                &signed_signature,
            ),
        ))
        .unwrap();
        now!(store.save_kyber_pre_key(
            1.into(),
            &KyberPreKeyRecord::new(
                1.into(),
                Timestamp::from_epoch_millis(1),
                &kyber,
                &kyber_signature,
            ),
        ))
        .unwrap();
        let bundle = PreKeyBundle::new(
            2,
            DeviceId::new(1).unwrap(),
            None,
            1.into(),
            signed.public_key,
            signed_signature.to_vec(),
            1.into(),
            kyber.public_key,
            kyber_signature.to_vec(),
            *identity.identity_key(),
        )
        .unwrap();
        (store, bundle)
    }

    /// Alice sends Bob two messages at once, from two ciphers on her one store;
    /// what Bob decrypts of each.
    async fn two_at_once(
        lock: impl Fn() -> SessionLock,
    ) -> Vec<Result<Vec<u8>>> {
        let (alice, bob_address) = (address(1), address(2));
        let mut csprng = rng();
        let store = Yielding(Rc::new(RefCell::new(
            InMemSignalProtocolStore::new(
                IdentityKeyPair::generate(&mut csprng),
                1,
            )
            .unwrap(),
        )));
        let (mut bob, bundle) = bob();
        process_prekey_bundle(
            &bob_address,
            &alice,
            &mut store.clone(),
            &mut store.clone(),
            &bundle,
            std::time::SystemTime::now(),
            &mut csprng,
        )
        .await
        .unwrap();
        let cipher = |lock| {
            ServiceCipher::new(store.clone(), vec![], alice.clone())
                .with_session_lock(lock)
        };
        let (mut one, mut two) = (cipher(lock()), cipher(lock()));
        let (mut rng_one, mut rng_two) = (rng(), rng());
        let (one, two) = futures::join!(
            one.encrypt(&bob_address, None, b"one", &mut rng_one),
            two.encrypt(&bob_address, None, b"two", &mut rng_two),
        );
        let mut decrypted = vec![];
        for message in [one, two] {
            let bytes =
                BASE64_RELAXED.decode(message.unwrap().content).unwrap();
            let message = CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(&bytes[..]).unwrap(),
            );
            let plaintext = message_decrypt(
                &message,
                &alice,
                &bob_address,
                &mut bob.session_store,
                &mut bob.identity_store,
                &mut bob.pre_key_store,
                &bob.signed_pre_key_store,
                &mut bob.kyber_pre_key_store,
                &mut rng(),
            )
            .await;
            decrypted.push(plaintext);
        }
        decrypted
    }

    /// Without one lock, both messages go out with one counter, and the second
    /// is lost.
    #[tokio::test]
    async fn two_sends_at_once_share_a_counter() {
        let decrypted = two_at_once(SessionLock::default).await;
        assert!(decrypted[0].is_ok());
        assert!(
            matches!(
                decrypted[1],
                Err(SignalProtocolError::DuplicatedMessage(_, 0))
            ),
            "{:?}",
            decrypted[1]
        );
    }

    #[tokio::test]
    async fn two_sends_under_one_lock_both_arrive() {
        let lock = SessionLock::default();
        let decrypted = two_at_once(|| lock.clone()).await;
        assert!(decrypted.iter().all(Result::is_ok), "{decrypted:?}");
    }
}
