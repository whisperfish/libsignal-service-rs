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
            ChallengeType::Captcha => Some("captcha".to_owned()),
            ChallengeType::PushChallenge => Some("pushChallenge".to_owned()),
            ChallengeType::Unspecified => None,
        })
        .collect();
    ProofRequired {
        token: c.token,
        options,
    }
}
