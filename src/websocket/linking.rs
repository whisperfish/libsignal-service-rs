use libsignal_core::DeviceId;
use libsignal_net_grpc::proto::chat::device::{
    devices_client::DevicesClient, RemoveDeviceRequest,
};

use crate::websocket::{self, SignalWebSocket};

use super::ServiceError;

impl SignalWebSocket<websocket::Identified> {
    pub async fn unlink_device(
        &mut self,
        id: DeviceId,
    ) -> Result<(), ServiceError> {
        DevicesClient::new(self.grpc.authenticated()?)
            .remove_device(RemoveDeviceRequest {
                id: u8::from(id).into(),
            })
            .await?;
        Ok(())
    }
}
