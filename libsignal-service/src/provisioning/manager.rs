use derivative::Derivative;
use futures::{channel::mpsc::Sender, pin_mut, SinkExt, StreamExt};
use libsignal_protocol::{PrivateKey, PublicKey};
use phonenumber::PhoneNumber;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use super::{
    pipe::{ProvisioningPipe, ProvisioningStep},
    ProvisioningError,
};

use crate::{
    configuration::{Endpoint, ServiceCredentials, SignalingKey},
    push_service::{
        DeviceId, HttpAuthOverride, PushService, ServiceError, ServiceIds,
    },
    utils::serde_base64,
};

/// Message received when linking a new secondary device.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConfirmDeviceMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub fetches_messages: bool,
    pub registration_id: u32,
    pub pni_registration_id: u32,
    #[serde(with = "serde_base64", skip_serializing_if = "Vec::is_empty")]
    pub name: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeResponse {
    pub uuid: Uuid,
    pub storage_capable: bool,
}

pub struct ProvisioningManager<'a, P: PushService + 'a> {
    push_service: &'a mut P,
    phone_number: PhoneNumber,
    password: String,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        phone_number: phonenumber::PhoneNumber,
        device_id: DeviceId,
        registration_id: u32,
        pni_registration_id: u32,
        service_ids: ServiceIds,
        #[derivative(Debug = "ignore")]
        aci_private_key: PrivateKey,
        aci_public_key: PublicKey,
        #[derivative(Debug = "ignore")]
        pni_private_key: PrivateKey,
        pni_public_key: PublicKey,
        #[derivative(Debug = "ignore")]
        profile_key: Vec<u8>,
    },
}

impl<'a, P: PushService + 'a> ProvisioningManager<'a, P> {
    pub fn new(
        push_service: &'a mut P,
        phone_number: PhoneNumber,
        password: String,
    ) -> Self {
        Self {
            push_service,
            phone_number,
            password,
        }
    }

    pub(crate) async fn confirm_device(
        &mut self,
        confirm_code: &str,
        confirm_code_message: ConfirmDeviceMessage,
    ) -> Result<DeviceId, ServiceError> {
        self.push_service
            .put_json(
                Endpoint::Service,
                &format!("/v1/devices/{}", confirm_code),
                self.auth_override(),
                confirm_code_message,
            )
            .await
    }

    fn auth_override(&self) -> HttpAuthOverride {
        let credentials = ServiceCredentials {
            uuid: None,
            phonenumber: self.phone_number.clone(),
            password: Some(self.password.clone()),
            signaling_key: None,
            device_id: None,
        };
        if let Some(auth) = credentials.authorization() {
            HttpAuthOverride::Identified(auth)
        } else {
            HttpAuthOverride::NoOverride
        }
    }
}

#[derive(Clone)]
pub struct LinkingManager<P: PushService> {
    push_service: P,
    // forwarded to the `ProvisioningManager`
    password: String,
}

impl<P: PushService> LinkingManager<P> {
    pub fn new(push_service: P, password: String) -> Self {
        Self {
            push_service,
            password,
        }
    }

    pub async fn provision_secondary_device<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        csprng: &mut R,
        signaling_key: SignalingKey,
        mut tx: Sender<SecondaryDeviceProvisioning>,
    ) -> Result<(), ProvisioningError> {
        // open a websocket without authentication, to receive a tsurl://
        let ws = self
            .push_service
            .ws("/v1/websocket/provisioning/", None, false)
            .await?;

        let registration_id = csprng.gen_range(1, 256);
        let pni_registration_id = csprng.gen_range(1, 256);

        let provisioning_pipe = ProvisioningPipe::from_socket(ws)?;
        let provision_stream = provisioning_pipe.stream();
        pin_mut!(provision_stream);
        while let Some(step) = provision_stream.next().await {
            match step {
                Ok(ProvisioningStep::Url(url)) => {
                    tx.send(SecondaryDeviceProvisioning::Url(url))
                        .await
                        .expect("failed to send provisioning Url in channel");
                },
                Ok(ProvisioningStep::Message(message)) => {
                    let aci_uuid = message
                        .aci
                        .ok_or(ProvisioningError::InvalidData {
                            reason: "missing client UUID".into(),
                        })
                        .and_then(|ref s| {
                            Uuid::parse_str(s).map_err(|e| {
                                ProvisioningError::InvalidData {
                                    reason: format!("invalid UUID: {}", e),
                                }
                            })
                        })?;

                    let pni_uuid = message
                        .pni
                        .ok_or(ProvisioningError::InvalidData {
                            reason: "missing client UUID".into(),
                        })
                        .and_then(|ref s| {
                            Uuid::parse_str(s).map_err(|e| {
                                ProvisioningError::InvalidData {
                                    reason: format!("invalid UUID: {}", e),
                                }
                            })
                        })?;

                    let aci_public_key = PublicKey::deserialize(
                        &message.aci_identity_key_public.ok_or(
                            ProvisioningError::InvalidData {
                                reason: "missing public key".into(),
                            },
                        )?,
                    )?;

                    let aci_private_key = PrivateKey::deserialize(
                        &message.aci_identity_key_private.ok_or(
                            ProvisioningError::InvalidData {
                                reason: "missing public key".into(),
                            },
                        )?,
                    )?;

                    let pni_public_key = PublicKey::deserialize(
                        &message.pni_identity_key_public.ok_or(
                            ProvisioningError::InvalidData {
                                reason: "missing public key".into(),
                            },
                        )?,
                    )?;

                    let pni_private_key = PrivateKey::deserialize(
                        &message.pni_identity_key_private.ok_or(
                            ProvisioningError::InvalidData {
                                reason: "missing public key".into(),
                            },
                        )?,
                    )?;

                    let profile_key = message.profile_key.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing profile key".into(),
                        },
                    )?;

                    let phone_number = message.number.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "missing phone number".into(),
                        },
                    )?;

                    let phone_number = phonenumber::parse(None, phone_number)
                        .map_err(|e| {
                        ProvisioningError::InvalidData {
                            reason: format!("invalid phone number ({})", e),
                        }
                    })?;

                    let mut provisioning_manager = ProvisioningManager::new(
                        &mut self.push_service,
                        phone_number.clone(),
                        self.password.clone(),
                    );

                    let provisioning_code = message.provisioning_code.ok_or(
                        ProvisioningError::InvalidData {
                            reason: "no provisioning confirmation code".into(),
                        },
                    )?;

                    let device_id = provisioning_manager
                        .confirm_device(
                            &provisioning_code,
                            ConfirmDeviceMessage {
                                signaling_key: signaling_key.to_vec(),
                                supports_sms: false,
                                fetches_messages: true,
                                registration_id,
                                pni_registration_id,
                                name: vec![],
                            },
                        )
                        .await?;

                    tx.send(
                        SecondaryDeviceProvisioning::NewDeviceRegistration {
                            phone_number,
                            device_id,
                            registration_id,
                            pni_registration_id,
                            service_ids: ServiceIds {
                                aci: aci_uuid,
                                pni: pni_uuid,
                            },
                            aci_private_key,
                            aci_public_key,
                            pni_private_key,
                            pni_public_key,
                            profile_key,
                        },
                    )
                    .await
                    .expect(
                        "failed to send provisioning message in rx channel",
                    );
                },
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
}
