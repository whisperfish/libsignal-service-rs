use crate::push_service::AttachmentV2UploadAttributes;

use super::*;

impl SignalWebSocket {
    #[deprecated]
    pub async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.get_json("/v2/attachments/form/upload").await
    }

    pub async fn get_attachment_v4_upload_form(
        &mut self,
    ) -> Result<AttachmentV4UploadForm, ServiceError> {
        self.get_json("/v4/attachments/form/upload").await
    }
}
