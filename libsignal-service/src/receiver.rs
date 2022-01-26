use bytes::{Buf, Bytes};

use crate::{
    attachment_cipher::decrypt_in_place,
    configuration::ServiceCredentials,
    envelope::Envelope,
    messagepipe::MessagePipe,
    models::{Contact, ParseContactError},
    push_service::*,
};

/// Equivalent of Java's `SignalServiceMessageReceiver`.
#[derive(Clone)]
pub struct MessageReceiver<Service> {
    service: Service,
}

#[derive(thiserror::Error, Debug)]
pub enum MessageReceiverError {
    #[error("ServiceError")]
    ServiceError(#[from] ServiceError),

    #[error("Envelope parsing error")]
    EnvelopeParseError(#[from] crate::envelope::EnvelopeParseError),
}

impl<Service: PushService> MessageReceiver<Service> {
    // TODO: to avoid providing the wrong service/wrong credentials
    // change it like LinkingManager or ProvisioningManager
    pub fn new(service: Service) -> Self {
        MessageReceiver { service }
    }

    /// One-off method to receive all pending messages.
    ///
    /// Equivalent with Java's `SignalServiceMessageReceiver::retrieveMessages`.
    ///
    /// For streaming messages, use a `MessagePipe` through
    /// [`MessageReceiver::create_message_pipe()`].
    pub async fn retrieve_messages(
        &mut self,
    ) -> Result<Vec<Envelope>, MessageReceiverError> {
        use std::convert::TryFrom;

        let entities = self.service.get_messages().await?;
        let entities = entities
            .into_iter()
            .map(Envelope::try_from)
            .collect::<Result<_, _>>()?;
        Ok(entities)
    }

    pub async fn create_message_pipe(
        &mut self,
        credentials: ServiceCredentials,
    ) -> Result<MessagePipe<Service::WebSocket>, MessageReceiverError> {
        let (ws, stream) = self
            .service
            .ws("/v1/websocket/", Some(credentials.clone()))
            .await?;
        Ok(MessagePipe::from_socket(ws, stream, credentials))
    }

    pub async fn retrieve_contacts(
        &mut self,
        contacts: &crate::proto::sync_message::Contacts,
    ) -> Result<
        impl Iterator<Item = Result<Contact, ParseContactError>>,
        ServiceError,
    > {
        if let Some(ref blob) = contacts.blob {
            use futures::io::AsyncReadExt;

            const MAX_DOWNLOAD_RETRIES: u8 = 3;
            let mut retries = 0;

            let mut stream = loop {
                let r = self.service.get_attachment(blob).await;
                match r {
                    Ok(stream) => break stream,
                    Err(ServiceError::Timeout { .. }) => {
                        log::warn!("get_attachment timed out, retrying");
                        retries += 1;
                        if retries >= MAX_DOWNLOAD_RETRIES {
                            return Err(ServiceError::Timeout {
                                reason: "too many retries".into(),
                            });
                        }
                    },
                    Err(e) => return Err(e),
                }
            };

            let mut ciphertext = Vec::new();
            stream
                .read_to_end(&mut ciphertext)
                .await
                .expect("streamed attachment");

            let key_material = blob.key();
            assert_eq!(
                key_material.len(),
                64,
                "key material for attachments is ought to be 64 bytes"
            );
            let mut key = [0u8; 64];
            key.copy_from_slice(key_material);

            decrypt_in_place(key, &mut ciphertext)
                .expect("attachment decryption");

            Ok(DeviceContactsIterator::new(Bytes::from(ciphertext)))
        } else {
            Ok(DeviceContactsIterator::default())
        }
    }
}

#[derive(Default)]
struct DeviceContactsIterator {
    decrypted_buffer: Bytes,
}

impl DeviceContactsIterator {
    fn new(decrypted_buffer: Bytes) -> Self {
        Self { decrypted_buffer }
    }
}

impl Iterator for DeviceContactsIterator {
    type Item = Result<Contact, ParseContactError>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::proto::{contact_details::Avatar, ContactDetails};

        if !self.decrypted_buffer.has_remaining() {
            return None;
        }

        let contact_details: ContactDetails =
            prost::Message::decode_length_delimited(&mut self.decrypted_buffer)
                .map_err(ParseContactError::ProtobufError)
                .ok()?;

        let avatar_data = if let Some(Avatar {
            length: Some(length),
            ..
        }) = contact_details.avatar
        {
            Some(self.decrypted_buffer.copy_to_bytes(length as usize))
        } else {
            None
        };

        Some(Contact::from_proto(contact_details, avatar_data))
    }
}
