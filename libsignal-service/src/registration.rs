use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceId {
    device_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCodeMessage {
    signaling_key: String,
    supports_sms: bool,
    fetches_messages: bool,
    registration_id: bool,
    name: bool,
}
