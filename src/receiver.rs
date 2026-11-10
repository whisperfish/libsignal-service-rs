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
            strip_attachment_padding(&mut ciphertext, blob.size);

            Ok(DeviceContactsIterator::new(Bytes::from(ciphertext)))
        } else {
            Ok(DeviceContactsIterator::default())
        }
    }
}

/// Drops the zero padding after the `size` bytes the sender declared;
/// otherwise each padding byte parses as an empty contact.
fn strip_attachment_padding(plaintext: &mut Vec<u8>, size: Option<u32>) {
    match size {
        Some(size) if size as usize <= plaintext.len() => {
            plaintext.truncate(size as usize)
        },
        Some(size) => tracing::warn!(
            size,
            plaintext = plaintext.len(),
            "attachment shorter than its declared size"
        ),
        None => {},
    }
}

#[derive(Default)]
struct DeviceContactsIterator {
    decrypted_buffer: Bytes,
    total: usize,
    parsed: usize,
}

impl DeviceContactsIterator {
    fn new(decrypted_buffer: Bytes) -> Self {
        Self {
            total: decrypted_buffer.len(),
            decrypted_buffer,
            parsed: 0,
        }
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

        let avatar_data = match contact_details.avatar {
            Some(Avatar {
                length: Some(length),
                ..
            }) => {
                let needed = length as usize;
                let remaining = self.decrypted_buffer.remaining();
                if needed > remaining {
                    tracing::warn!(
                        parsed = self.parsed,
                        needed,
                        remaining,
                        total = self.total,
                        "contact avatar runs past the end of the contacts; stopping"
                    );
                    self.decrypted_buffer.clear();
                    return Some(Err(ParseContactError::Truncated {
                        needed,
                        remaining,
                    }));
                }
                Some(self.decrypted_buffer.copy_to_bytes(needed))
            },
            Some(Avatar { length: None, .. }) => {
                tracing::warn!(
                    parsed = self.parsed,
                    "contact avatar without a length"
                );
                None
            },
            None => None,
        };
        self.parsed += 1;

        Some(Contact::from_proto(contact_details, avatar_data))
    }
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use prost::Message;

    use super::*;
    use crate::proto::{contact_details::Avatar, ContactDetails};

    fn details(avatar_length: Option<u32>) -> ContactDetails {
        ContactDetails {
            aci: Some("9d0652a3-dcc3-4d11-975f-74d61598733f".into()),
            name: Some("Contact".into()),
            avatar: avatar_length.map(|length| Avatar {
                content_type: Some("image/png".into()),
                length: Some(length),
            }),
            ..Default::default()
        }
    }

    /// Length-delimited details, each followed by `avatar_bytes` bytes.
    fn buffer(parts: &[(ContactDetails, usize)]) -> Bytes {
        let mut buffer = BytesMut::new();
        for (details, avatar_bytes) in parts {
            details.encode_length_delimited(&mut buffer).unwrap();
            buffer.put_bytes(0xaa, *avatar_bytes);
        }
        buffer.freeze()
    }

    #[test]
    fn reads_contacts_with_and_without_avatars() {
        let contacts: Vec<_> = DeviceContactsIterator::new(buffer(&[
            (details(Some(3)), 3),
            (details(None), 0),
        ]))
        .collect();

        assert_eq!(contacts.len(), 2);
        assert!(contacts.iter().all(Result::is_ok));
    }

    #[test]
    fn truncated_avatar_ends_iteration_instead_of_panicking() {
        let mut contacts = DeviceContactsIterator::new(buffer(&[
            (details(None), 0),
            (details(Some(100)), 10),
            (details(None), 0),
        ]));

        assert!(contacts.next().unwrap().is_ok());
        assert!(matches!(
            contacts.next(),
            Some(Err(ParseContactError::Truncated { needed: 100, .. }))
        ));
        assert!(contacts.next().is_none());
    }

    #[test]
    fn padding_is_stripped_to_the_declared_size() {
        let contacts = buffer(&[(details(Some(3)), 3), (details(None), 0)]);
        let size = contacts.len() as u32;
        let mut plaintext = contacts.to_vec();
        plaintext.resize(plaintext.len() + 50, 0);

        strip_attachment_padding(&mut plaintext, Some(size));
        let parsed: Vec<_> =
            DeviceContactsIterator::new(Bytes::from(plaintext)).collect();

        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().all(Result::is_ok));
    }

    #[test]
    fn short_plaintext_is_kept_whole() {
        let mut plaintext = vec![1, 2, 3];
        strip_attachment_padding(&mut plaintext, Some(10));
        assert_eq!(plaintext, [1, 2, 3]);

        strip_attachment_padding(&mut plaintext, None);
        assert_eq!(plaintext, [1, 2, 3]);
    }
}
