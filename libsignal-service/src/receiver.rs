use bytes::{Buf, Bytes};
use log::info;

use crate::{
    attachment_cipher::decrypt_in_place,
    configuration::ServiceCredentials,
    envelope::Envelope,
    messagepipe::MessagePipe,
    models::{Contact, ParseContactError},
    proto::{AttachmentPointer, GroupDetails, group_details::Avatar},
    push_service::*, groups_v2::GroupDecodingError,
};

const MAX_ATTACHMENT_RETRIES: u8 = 3;

/// Equivalent of Java's `SignalServiceMessageReceiver`.
#[derive(Clone)]
pub struct MessageReceiver<Service> {
    service: Service,
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
    ) -> Result<Vec<Envelope>, ServiceError> {
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
    ) -> Result<MessagePipe, ServiceError> {
        let ws = self
            .service
            .ws("/v1/websocket/", Some(credentials.clone()), true)
            .await?;
        Ok(MessagePipe::from_socket(ws, credentials))
    }

    async fn get_attachment(
        &mut self,
        attachment: AttachmentPointer,
        max_retries: u8,
    ) -> Result<Bytes, ServiceError> {
        use futures::io::AsyncReadExt;

        let mut retries = 0;
        let mut stream = loop {
            let r = self.service.get_attachment(&attachment).await;
            match r {
                Ok(stream) => break stream,
                Err(ServiceError::Timeout { .. }) => {
                    log::warn!("get_attachment timed out, retrying");
                    retries += 1;
                    if retries >= max_retries {
                        return Err(ServiceError::Timeout {
                            reason: "too many retries",
                        });
                    }
                },
                Err(e) => return Err(e),
            }
        };

        let mut ciphertext = Vec::with_capacity(dbg!(attachment.size() as usize));
        stream
            .read_to_end(&mut ciphertext)
            .await
            .expect("streamed attachment");

        let key_material = attachment.key();
        assert_eq!(
            key_material.len(),
            64,
            "key material for attachments is ought to be 64 bytes"
        );
        dbg!(key_material.len());
        let mut key = [0u8; 64];
        key.copy_from_slice(key_material);

        decrypt_in_place(key, &mut ciphertext).expect("attachment decryption");

        Ok(Bytes::from(ciphertext))
    }

    pub async fn retrieve_contacts(
        &mut self,
        contacts: crate::proto::sync_message::Contacts,
    ) -> Result<
        impl Iterator<Item = Result<Contact, ParseContactError>>,
        ServiceError,
    > {
        let attachment = contacts.blob.ok_or(ParseContactError::MissingBlob)?;
        let bytes = self
            .get_attachment(attachment, MAX_ATTACHMENT_RETRIES)
            .await?;
        Ok(DeviceContactsIterator::new(bytes))
    }

    pub async fn retrieve_groups(
        &mut self,
        groups: crate::proto::sync_message::Groups,
    ) -> Result<
        impl Iterator<Item = Result<GroupDetails, GroupDecodingError>>,
        ServiceError,
    > {
        let attachment = groups.blob.ok_or(GroupDecodingError::WrongBlob)?;
        let bytes = self
            .get_attachment(attachment, MAX_ATTACHMENT_RETRIES)
            .await?;
        Ok(DeviceGroupsIterator::new(bytes))
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

#[derive(Default)]
struct DeviceGroupsIterator {
    decrypted_buffer: Bytes,
}

impl DeviceGroupsIterator {
    fn new(decrypted_buffer: Bytes) -> Self {
        Self { decrypted_buffer }
    }
}

impl Iterator for DeviceGroupsIterator {
    type Item = Result<GroupDetails, GroupDecodingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.decrypted_buffer.has_remaining() {
            return None;
        }

        let group_details: GroupDetails =
            prost::Message::decode_length_delimited(&mut self.decrypted_buffer)
                .map_err(GroupDecodingError::ProtobufDecodeError)
                .ok()?;

        let avatar_data = if let Some(Avatar {
            length: Some(length),
            ..
        }) = group_details.avatar
        {
            info!("GOT GROUP AVATAR DATA");
            Some(self.decrypted_buffer.copy_to_bytes(length as usize))
        } else {
            None
        };
        dbg!(self.decrypted_buffer.remaining());

        Some(Ok(group_details))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::DeviceGroupsIterator;

    #[test]
    fn decode_groups() {
        let bytes = Bytes::from(std::fs::read("/Users/gferon/Downloads/2738893419980511538").unwrap());
        let it = DeviceGroupsIterator::new(bytes);
        for g in it {
            dbg!(g);
        }
    }
}