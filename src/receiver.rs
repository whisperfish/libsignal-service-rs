use bytes::{Buf, Bytes};

use crate::{
    attachment_cipher::{decrypt_in_place, AttachmentCipherError},
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
            stream.read_to_end(&mut ciphertext).await?;

            let key: [u8; 64] = blob.key().try_into().map_err(|_| {
                ServiceError::InvalidFrame {
                    reason:
                        "key material for attachments is ought to be 64 bytes",
                }
            })?;

            decrypt_in_place(key, &mut ciphertext).map_err(|e| match e {
                AttachmentCipherError::MacError => ServiceError::MacError,
                AttachmentCipherError::PaddingError => {
                    ServiceError::InvalidFrame {
                        reason: "invalid padding in the contacts attachment",
                    }
                },
            })?;

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

        let mut contact_details: ContactDetails =
            prost::Message::decode_length_delimited(&mut self.decrypted_buffer)
                .map_err(ParseContactError::Protobuf)
                .ok()?;

        let avatar_data = if let Some(Avatar {
            length: Some(length),
            ..
        }) = contact_details.avatar
        {
            let length = length as usize;
            let remaining = self.decrypted_buffer.remaining();
            if length > remaining {
                // Some senders announce avatars they never write; nothing
                // after this point can be trusted.
                tracing::warn!(
                    length,
                    remaining,
                    "contact avatar runs past the end of the contact list"
                );
                self.decrypted_buffer.clear();
                contact_details.avatar = None;
                None
            } else {
                Some(self.decrypted_buffer.copy_to_bytes(length))
            }
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
    use crate::proto::{contact_details::Avatar, ContactDetails};

    fn contact(aci: &str, avatar_length: Option<u32>) -> ContactDetails {
        ContactDetails {
            aci: Some(aci.into()),
            name: Some(aci.into()),
            avatar: avatar_length.map(|length| Avatar {
                content_type: Some("image/jpeg".into()),
                length: Some(length),
            }),
            ..Default::default()
        }
    }

    fn list(parts: &[&[u8]]) -> DeviceContactsIterator {
        DeviceContactsIterator::new(Bytes::from(parts.concat()))
    }

    const ALICE: &str = "c6191523-0f40-4179-951f-9b442ed562be";
    const BOB: &str = "0124bb41-d3a5-4963-b2de-192e6aaebd39";

    #[test]
    fn avatars_are_read_after_their_contact() {
        let mut parts = Vec::new();
        contact(ALICE, Some(3))
            .encode_length_delimited(&mut parts)
            .unwrap();
        parts.extend_from_slice(b"abc");
        contact(BOB, None)
            .encode_length_delimited(&mut parts)
            .unwrap();

        let contacts: Vec<_> = list(&[&parts]).map(Result::unwrap).collect();
        assert_eq!(contacts.len(), 2);
        assert_eq!(&contacts[0].avatar.as_ref().unwrap().reader[..], b"abc");
        assert!(contacts[1].avatar.is_none());
    }

    #[test]
    fn an_avatar_past_the_end_of_the_list_does_not_panic() {
        let mut parts = Vec::new();
        contact(ALICE, Some(14020))
            .encode_length_delimited(&mut parts)
            .unwrap();
        contact(BOB, None)
            .encode_length_delimited(&mut parts)
            .unwrap();

        let mut contacts = list(&[&parts]);
        let first = contacts.next().unwrap().unwrap();
        assert_eq!(first.uuid.to_string(), ALICE);
        assert!(first.avatar.is_none());
        assert!(contacts.next().is_none());
    }
}
