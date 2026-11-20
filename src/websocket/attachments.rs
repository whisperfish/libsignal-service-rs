use libsignal_net_grpc::proto::chat::attachments::{
    attachments_client::AttachmentsClient, get_upload_form_response,
    GetUploadFormRequest,
};
use libsignal_net_grpc::proto::chat::common::UploadForm;

use crate::push_service::{AttachmentUploadForm, ServiceError};

use super::{Identified, SignalWebSocket};

impl SignalWebSocket<Identified> {
    pub(crate) async fn get_attachment_upload_form(
        &mut self,
        upload_length: u64,
    ) -> Result<AttachmentUploadForm, ServiceError> {
        use get_upload_form_response::Outcome;
        let response = AttachmentsClient::new(self.grpc.authenticated()?)
            .get_upload_form(GetUploadFormRequest { upload_length })
            .await?
            .into_inner();
        match response.outcome {
            Some(Outcome::UploadForm(UploadForm {
                cdn,
                key,
                headers,
                signed_upload_location,
            })) => Ok(AttachmentUploadForm {
                cdn,
                key,
                headers,
                signed_upload_location: signed_upload_location.parse()?,
            }),
            Some(Outcome::ExceedsMaxUploadLength(_)) => {
                Err(ServiceError::AttachmentTooLarge)
            },
            None => Err(ServiceError::InvalidFrame {
                reason: "empty GetUploadForm response",
            }),
        }
    }
}
