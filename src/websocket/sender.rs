
use libsignal_core::DeviceId;
use libsignal_net_grpc::proto::chat::messages::{
    challenge_required::ChallengeType,
    individual_recipient_message_bundle::Message,
    messages_anonymous_client::MessagesAnonymousClient,
    messages_client::MessagesClient,
    send_message_authenticated_sender_response, send_message_response,
    send_sealed_sender_message_request, ChallengeRequired,
    IndividualRecipientMessageBundle, MismatchedDevices,
    SendAuthenticatedSenderMessageRequest, SendMessageType,
    SendSealedSenderMessageRequest, SendSyncMessageRequest,
};

use crate::{
    proto::envelope,
    push_service::{self, ProofRequired},
    sender::{OutgoingPushMessages, SendMessageResponse},
    unidentified_access::UnidentifiedAccess,
    utils::BASE64_RELAXED,
};

use super::*;
use base64::Engine;

impl<C: WebSocketType> SignalWebSocket<C> {
    pub async fn send_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let destination = messages.destination;
        let ephemeral = messages.online;
        let response = MessagesClient::new(self.grpc.authenticated()?)
            .send_message(SendAuthenticatedSenderMessageRequest {
                destination: Some(destination.into()),
                ephemeral,
                urgent: true,
                messages: Some(bundle(messages)?),
            })
            .await?
            .into_inner();
        authenticated_sender_response(response.response)
    }

    /// Sends a message to the other devices linked to our own account.
    pub async fn send_sync_messages(
        &mut self,
        messages: OutgoingPushMessages,
    ) -> Result<SendMessageResponse, ServiceError> {
        let response = MessagesClient::new(self.grpc.authenticated()?)
            .send_sync_message(SendSyncMessageRequest {
                urgent: true,
                messages: Some(bundle(messages)?),
            })
            .await?
            .into_inner();
        authenticated_sender_response(response.response)
    }

    pub async fn send_messages_unidentified(
        &mut self,
        messages: OutgoingPushMessages,
        access: &UnidentifiedAccess,
    ) -> Result<SendMessageResponse, ServiceError> {
        use send_message_response::Response;

        let destination = messages.destination;
        let ephemeral = messages.online;
        let response =
            MessagesAnonymousClient::new(self.grpc.unauthenticated())
                .send_single_recipient_message(
                    SendSealedSenderMessageRequest {
                        destination: Some(destination.into()),
                        ephemeral,
                        urgent: true,
                        messages: Some(bundle(messages)?),
                        authorization: Some(
                            send_sealed_sender_message_request::Authorization::UnidentifiedAccessKey(
                                access.key.clone(),
                            ),
                        ),
                    },
                )
                .await?
                .into_inner();
        match response.response {
            Some(Response::Success(())) => Ok(sent()),
            Some(Response::MismatchedDevices(m)) => Err(mismatched(m)?),
            Some(Response::FailedUnidentifiedAuthorization(_)) => {
                Err(ServiceError::Unauthorized)
            },
            Some(Response::DestinationNotFound(_)) => {
                Err(ServiceError::UnregisteredRecipient)
            },
            None => Err(empty_response()),
        }
    }
}

fn sent() -> SendMessageResponse {
    SendMessageResponse { needs_sync: false }
}

fn empty_response() -> ServiceError {
    ServiceError::InvalidFrame {
        reason: "empty send message response",
    }
}

fn authenticated_sender_response(
    response: Option<send_message_authenticated_sender_response::Response>,
) -> Result<SendMessageResponse, ServiceError> {
    use send_message_authenticated_sender_response::Response;
    match response {
        Some(Response::Success(())) => Ok(sent()),
        Some(Response::MismatchedDevices(m)) => Err(mismatched(m)?),
        Some(Response::ChallengeRequired(c)) => {
            Err(ServiceError::ProofRequiredError(proof_required(c)))
        },
        Some(Response::DestinationNotFound(_)) => {
            Err(ServiceError::UnregisteredRecipient)
        },
        None => Err(empty_response()),
    }
}

fn bundle(
    messages: OutgoingPushMessages,
) -> Result<IndividualRecipientMessageBundle, ServiceError> {
    let timestamp = messages.timestamp;
    let messages = messages
        .messages
        .into_iter()
        .map(|m| {
            let r#type = match envelope::Type::try_from(m.r#type as i32) {
                Ok(envelope::Type::DoubleRatchet) => {
                    SendMessageType::DoubleRatchet
                },
                Ok(envelope::Type::PrekeyMessage) => {
                    SendMessageType::PrekeyMessage
                },
                Ok(envelope::Type::UnidentifiedSender) => {
                    SendMessageType::UnidentifiedSender
                },
                Ok(envelope::Type::PlaintextContent) => {
                    SendMessageType::PlaintextContent
                },
                _ => {
                    return Err(ServiceError::InvalidFrame {
                        reason: "unsupported outgoing message type",
                    })
                },
            };
            Ok((
                u8::from(m.destination_device_id).into(),
                Message {
                    registration_id: m.destination_registration_id,
                    payload: BASE64_RELAXED.decode(m.content)?,
                    r#type: r#type.into(),
                },
            ))
        })
        .collect::<Result<_, _>>()?;
    Ok(IndividualRecipientMessageBundle {
        timestamp,
        messages,
    })
}

fn device_ids(ids: Vec<u32>) -> Result<Vec<DeviceId>, ServiceError> {
    Ok(ids
        .into_iter()
        .map(DeviceId::try_from)
        .collect::<Result<_, _>>()?)
}

// Stale devices come bundled with missing/extra ones; the sender's retry picks them up next round.
fn mismatched(m: MismatchedDevices) -> Result<ServiceError, ServiceError> {
    if m.missing_devices.is_empty() && m.extra_devices.is_empty() {
        Ok(ServiceError::StaleDevices(push_service::StaleDevices {
            stale_devices: device_ids(m.stale_devices)?,
        }))
    } else {
        Ok(ServiceError::MismatchedDevicesException(
            push_service::MismatchedDevices {
                missing_devices: device_ids(m.missing_devices)?,
                extra_devices: device_ids(m.extra_devices)?,
            },
        ))
    }
}

fn proof_required(c: ChallengeRequired) -> ProofRequired {
    let options = c
        .challenge_options()
        .filter_map(|o| match o {
            ChallengeType::Captcha => Some("recaptcha".to_owned()),
            ChallengeType::PushChallenge => Some("pushChallenge".to_owned()),
            ChallengeType::Unspecified => None,
        })
        .collect();
    ProofRequired {
        token: c.token,
        options,
    }
}

#[cfg(test)]
mod tests {
    use libsignal_core::Aci;

    use super::*;
    use crate::sender::OutgoingPushMessage;

    fn device(id: u8) -> DeviceId {
        DeviceId::try_from(id).unwrap()
    }

    #[test]
    fn bundle_decodes_payload_and_maps_types() {
        let messages = OutgoingPushMessages {
            destination: Aci::from_uuid_bytes([1; 16]).into(),
            timestamp: 42,
            online: false,
            messages: vec![
                OutgoingPushMessage {
                    r#type: envelope::Type::PrekeyMessage as u32,
                    destination_device_id: device(1),
                    destination_registration_id: 7,
                    content: BASE64_RELAXED.encode([1, 2, 3]),
                },
                OutgoingPushMessage {
                    r#type: envelope::Type::UnidentifiedSender as u32,
                    destination_device_id: device(2),
                    destination_registration_id: 8,
                    content: BASE64_RELAXED.encode([4]),
                },
            ],
        };
        let bundle = bundle(messages).unwrap();
        assert_eq!(bundle.timestamp, 42);
        assert_eq!(bundle.messages[&1].payload, vec![1, 2, 3]);
        assert_eq!(bundle.messages[&1].registration_id, 7);
        assert_eq!(
            bundle.messages[&1].r#type(),
            SendMessageType::PrekeyMessage
        );
        assert_eq!(
            bundle.messages[&2].r#type(),
            SendMessageType::UnidentifiedSender
        );
    }

    #[test]
    fn mismatched_prefers_missing_and_extra_over_stale() {
        let error = mismatched(MismatchedDevices {
            service_identifier: None,
            missing_devices: vec![2],
            extra_devices: vec![],
            stale_devices: vec![3],
        })
        .unwrap();
        assert!(matches!(
            error,
            ServiceError::MismatchedDevicesException(m)
                if m.missing_devices == [device(2)] && m.extra_devices.is_empty()
        ));

        let error = mismatched(MismatchedDevices {
            service_identifier: None,
            missing_devices: vec![],
            extra_devices: vec![],
            stale_devices: vec![3],
        })
        .unwrap();
        assert!(matches!(
            error,
            ServiceError::StaleDevices(s) if s.stale_devices == [device(3)]
        ));
    }

    #[test]
    fn challenge_options_use_rest_names() {
        let proof = proof_required(ChallengeRequired {
            token: "t".into(),
            challenge_options: vec![
                ChallengeType::Captcha.into(),
                ChallengeType::PushChallenge.into(),
            ],
            retry_after_seconds: None,
        });
        assert_eq!(proof.token, "t");
        assert_eq!(proof.options, ["recaptcha", "pushChallenge"]);
    }
}
