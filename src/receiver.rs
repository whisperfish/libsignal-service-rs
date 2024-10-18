use bytes::{Buf, Bytes};

use crate::{
    attachment_cipher::decrypt_in_place,
    configuration::ServiceCredentials,
    messagepipe::MessagePipe,
    models::{Contact, ParseContactError},
    push_service::*,
};

/// Equivalent of Java's `SignalServiceMessageReceiver`.
#[derive(Clone)]
pub struct MessageReceiver {
    service: PushService,
}

impl MessageReceiver {
    // TODO: to avoid providing the wrong service/wrong credentials
    // change it like LinkingManager or ProvisioningManager
    pub fn new(service: PushService) -> Self {
        MessageReceiver { service }
    }

    pub async fn create_message_pipe(
        &mut self,
        credentials: ServiceCredentials,
        allow_stories: bool,
    ) -> Result<MessagePipe, ServiceError> {
        let headers = &[(
            "X-Signal-Receive-Stories",
            if allow_stories { "true" } else { "false" },
        )];
        let ws = self
            .service
            .ws(
                "/v1/websocket/",
                "/v1/keepalive",
                headers,
                Some(credentials.clone()),
            )
            .await?;
        Ok(MessagePipe::from_socket(ws, credentials))
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
                        tracing::warn!("get_attachment timed out, retrying");
                        retries += 1;
                        if retries >= MAX_DOWNLOAD_RETRIES {
                            return Err(ServiceError::Timeout {
                                reason: "too many retries",
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
                .map_err(ParseContactError::Protobuf)
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
