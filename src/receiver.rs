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
                Some(credentials),
            )
            .await?;
        Ok(MessagePipe::from_socket(ws))
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
                    Ok(download) => break download.stream,
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

            // A bad blob is an error, not a panic: the sync message is kept
            // and handled again, so a panic here stops receiving for good.
            let mut ciphertext = Vec::new();
            stream.read_to_end(&mut ciphertext).await?;

            // A key of another length can't decrypt it either.
            let key: [u8; 64] =
                blob.key().try_into().map_err(|_| ServiceError::MacError)?;

            decrypt_in_place(key, &mut ciphertext)
                .map_err(|_| ServiceError::MacError)?;

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
            let length = length as usize;
            if length > self.decrypted_buffer.remaining() {
                // The rest can't be read either.
                self.decrypted_buffer.clear();
                return Some(Err(ParseContactError::AvatarPastEnd));
            }
            Some(self.decrypted_buffer.copy_to_bytes(length))
        } else {
            None
        };

        Some(Contact::from_proto(contact_details, avatar_data))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use prost::Message;

    use super::DeviceContactsIterator;
    use crate::{
        models::ParseContactError,
        proto::{contact_details::Avatar, ContactDetails},
    };

    #[test]
    fn an_avatar_past_the_end_is_an_error() {
        let details = ContactDetails {
            aci: Some("9d0652a3-dcc3-4d11-975f-74d61598733f".into()),
            avatar: Some(Avatar {
                content_type: Some("image/jpeg".into()),
                length: Some(1000),
            }),
            ..Default::default()
        };
        let mut buffer = details.encode_length_delimited_to_vec();
        buffer.extend([0u8; 10]);
        let mut contacts = DeviceContactsIterator::new(Bytes::from(buffer));
        assert!(matches!(
            contacts.next(),
            Some(Err(ParseContactError::AvatarPastEnd))
        ));
        assert!(contacts.next().is_none());
    }
}
