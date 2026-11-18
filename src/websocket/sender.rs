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
                messages: Some(messages.into_bundle()?),
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
                messages: Some(messages.into_bundle()?),
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
                        messages: Some(messages.into_bundle()?),
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
            Some(Response::Success(())) => {
                Ok(SendMessageResponse { needs_sync: false })
            },
            Some(Response::MismatchedDevices(m)) => {
                Err(ServiceError::mismatched_devices(m)?)
            },
            Some(Response::FailedUnidentifiedAuthorization(_)) => {
                Err(ServiceError::Unauthorized)
            },
            Some(Response::DestinationNotFound(_)) => {
                Err(ServiceError::UnregisteredRecipient)
            },
            None => Err(ServiceError::empty_send_response()),
        }
    }
}

fn authenticated_sender_response(
    response: Option<send_message_authenticated_sender_response::Response>,
) -> Result<SendMessageResponse, ServiceError> {
    use send_message_authenticated_sender_response::Response;
    match response {
        Some(Response::Success(())) => {
            Ok(SendMessageResponse { needs_sync: false })
        },
        Some(Response::MismatchedDevices(m)) => {
            Err(ServiceError::mismatched_devices(m)?)
        },
        Some(Response::ChallengeRequired(c)) => Err(
            ServiceError::ProofRequiredError(ProofRequired::from_challenge(c)),
        ),
        Some(Response::DestinationNotFound(_)) => {
            Err(ServiceError::UnregisteredRecipient)
        },
        None => Err(ServiceError::empty_send_response()),
    }
}

impl ServiceError {
    fn empty_send_response() -> Self {
        ServiceError::InvalidFrame {
            reason: "empty send message response",
        }
    }

    // Stale devices come bundled with missing/extra ones; the sender's retry picks them up next round.
    fn mismatched_devices(m: MismatchedDevices) -> Result<Self, Self> {
        let device_ids = |ids: Vec<u32>| {
            ids.into_iter()
                .map(DeviceId::try_from)
                .collect::<Result<Vec<_>, _>>()
        };
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
}

impl ProofRequired {
    fn from_challenge(c: ChallengeRequired) -> Self {
        let options = c
            .challenge_options()
            .filter_map(|o| match o {
                ChallengeType::Captcha => Some("captcha".to_owned()),
                ChallengeType::PushChallenge => {
                    Some("pushChallenge".to_owned())
                },
                ChallengeType::Unspecified => None,
            })
            .collect();
        Self {
            token: c.token,
            options,
        }
    }
}

impl OutgoingPushMessages {
    fn into_bundle(
        self,
    ) -> Result<IndividualRecipientMessageBundle, ServiceError> {
        let timestamp = self.timestamp;
        let messages = self
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
}
