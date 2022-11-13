use futures::{channel::mpsc::Sender, pin_mut, SinkExt, StreamExt};
use url::Url;

use crate::push_service::AwcPushService;
use libsignal_protocol::{
    generate_registration_id,
    keys::{PrivateKey, PublicKey},
    Context,
};
use libsignal_service::{
    configuration::ServiceConfiguration,
    messagepipe::Credentials,
    prelude::PushService,
    provisioning::{ProvisioningError, ProvisioningPipe, ProvisioningStep},
    push_service::{ConfirmDeviceMessage, DeviceId},
    USER_AGENT,
};

#[derive(Debug)]
pub enum SecondaryDeviceProvisioning {
    Url(Url),
    NewDeviceRegistration {
        phone_number: String,
        device_id: DeviceId,
        registration_id: u32,
        uuid: String,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: Vec<u8>,
    },
}
