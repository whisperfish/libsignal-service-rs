use crate::push_service::AttachmentV2UploadAttributes;

use super::*;

impl SignalWebSocket {
    pub async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.get_json("/v2/attachments/form/upload").await
    }
}
