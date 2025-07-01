use crate::websocket::{self, SignalWebSocket};

use super::ServiceError;

impl<C: websocket::WebSocketType> SignalWebSocket<C> {
    pub async fn get_sticker_pack_manifest(
        &mut self,
        id: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("/stickers/{}/manifest.proto", id);
        self.unidentified_push_service.get_from_cdn(0, &path).await
    }

    pub async fn get_sticker(
        &mut self,
        pack_id: &str,
        sticker_id: u32,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("/stickers/{}/full/{}", pack_id, sticker_id);
        self.unidentified_push_service.get_from_cdn(0, &path).await
    }
}
