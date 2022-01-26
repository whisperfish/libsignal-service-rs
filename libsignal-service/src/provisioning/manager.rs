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
        AccountAttributes, DeviceCapabilities, DeviceId, HttpAuthOverride,
        PushService, ServiceError,
    },
    utils::{serde_base64, serde_optional_base64},
};

/// Message received after confirming the SMS/voice code on registration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub registration_id: u32,
    pub voice: bool,
    pub video: bool,
    pub fetches_messages: bool,
    pub pin: Option<String>,
    #[serde(default, with = "serde_optional_base64")]
    pub unidentified_access_key: Option<Vec<u8>>,
    pub unrestricted_unidentified_access: bool,
    pub discoverable_by_phone_number: bool,
    pub capabilities: DeviceCapabilities,
}
/// Message received when linking a new secondary device.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmDeviceMessage {
    #[serde(with = "serde_base64")]
    pub signaling_key: Vec<u8>,
    pub supports_sms: bool,
    pub fetches_messages: bool,
    pub registration_id: u32,
    // FIXME: the name goes back here when we send this via the websocket
    //pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeResponse {
    pub uuid: Uuid,
    pub storage_capable: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VerificationCodeResponse {
    CaptchaRequired,
    Issued,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyAccountResponse {
    pub uuid: Uuid,
    pub pni: String,
    pub storage_capable: bool,
}

pub struct ProvisioningManager<'a, P: PushService + 'a> {
    push_service: &'a mut P,
    phone_number: PhoneNumber,
    password: String,
}

pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        phone_number: phonenumber::PhoneNumber,
        device_id: DeviceId,
        registration_id: u32,
        uuid: Uuid,
        private_key: PrivateKey,
        public_key: PublicKey,
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

    pub async fn request_sms_verification_code(
        &mut self,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<VerificationCodeResponse, ServiceError> {
        let res = match self
            .push_service
            .get_json(
                Endpoint::Service,
                self.build_verification_code_request_url(
                    "sms", captcha, challenge,
                )
                .as_ref(),
                self.auth_override(),
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        };
        match res {
            Ok(_) => Ok(VerificationCodeResponse::Issued),
            Err(ServiceError::UnhandledResponseCode { http_code: 402 }) => {
                Ok(VerificationCodeResponse::CaptchaRequired)
            },
            Err(e) => Err(e),
        }
    }

    pub async fn request_voice_verification_code(
        &mut self,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> Result<VerificationCodeResponse, ServiceError> {
        let res = match self
            .push_service
            .get_json(
                Endpoint::Service,
                self.build_verification_code_request_url(
                    "voice", captcha, challenge,
                )
                .as_ref(),
                self.auth_override(),
            )
            .await
        {
            Err(ServiceError::JsonDecodeError { .. }) => Ok(()),
            r => r,
        };
        match res {
            Ok(_) => Ok(VerificationCodeResponse::Issued),
            Err(ServiceError::UnhandledResponseCode { http_code: 402 }) => {
                Ok(VerificationCodeResponse::CaptchaRequired)
            },
            Err(e) => Err(e),
        }
    }

    pub async fn confirm_verification_code(
        &mut self,
        confirm_code: u32,
        account_attributes: AccountAttributes,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        self.push_service
            .put_json(
                Endpoint::Service,
                &format!("/v1/accounts/code/{}", confirm_code),
                self.auth_override(),
                account_attributes,
            )
            .await
    }

    pub async fn confirm_device(
        &mut self,
        confirm_code: u32,
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

    fn build_verification_code_request_url(
        &self,
        msg_type: &str,
        captcha: Option<&str>,
        challenge: Option<&str>,
    ) -> String {
        let phone_number =
            self.phone_number.format().mode(phonenumber::Mode::E164);
        if let Some(cl) = challenge {
            format!(
                "/v1/accounts/{}/code/{}?challenge={}",
                msg_type, phone_number, cl
            )
        } else if let Some(cc) = captcha {
            format!(
                "/v1/accounts/{}/code/{}?captcha={}",
                msg_type, phone_number, cc
            )
        } else {
            format!("/v1/accounts/{}/code/{}", msg_type, phone_number)
        }
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
        let (ws, stream) = self
            .push_service
            .ws("/v1/websocket/provisioning/", None)
            .await?;

        // see libsignal-protocol-c / signal_protocol_key_helper_generate_registration_id
        let registration_id = csprng.gen_range(1, 16380);

        let provisioning_pipe = ProvisioningPipe::from_socket(ws, stream)?;
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
                    let uuid = message
                        .uuid
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

                    let public_key = PublicKey::deserialize(
                        &message.identity_key_public.ok_or(
                            ProvisioningError::InvalidData {
                                reason: "missing public key".into(),
                            },
                        )?,
                    )?;

                    let private_key = PrivateKey::deserialize(
                        &message.identity_key_private.ok_or(
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

                    let device_id = provisioning_manager
                        .confirm_device(
                            message
                                .provisioning_code
                                .ok_or(ProvisioningError::InvalidData {
                                    reason: "no provisioning confirmation code"
                                        .into(),
                                })?
                                .parse()
                                .unwrap(),
                            ConfirmDeviceMessage {
                                signaling_key: signaling_key.to_vec(),
                                supports_sms: false,
                                fetches_messages: true,
                                registration_id,
                            },
                        )
                        .await?;

                    tx.send(
                        SecondaryDeviceProvisioning::NewDeviceRegistration {
                            phone_number,
                            device_id,
                            registration_id,
                            uuid,
                            private_key,
                            public_key,
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
