use crate::push_service::{
    AttachmentUploadForm, ResumableUploadSpec, ResumeInfo,
};

use super::*;

impl SignalWebSocket {
    pub(crate) async fn get_attachment_v4_upload_attributes(
        &mut self,
    ) -> Result<AttachmentUploadForm, ServiceError> {
        self.get_json("/v4/attachments/form/upload").await
    }

    pub(crate) async fn get_resumable_upload_url(
        &mut self,
        attachment_upload_form: &AttachmentUploadForm,
    ) -> Result<ResumableUploadSpec, ServiceError> {
        let mut headers = attachment_upload_form.headers.clone();
        headers.insert("Content-Length".into(), "0".into());
        if attachment_upload_form.cdn == 2 {
            headers.insert(
                "Content-Type".into(),
                "application/octet-stream".into(),
            );
        } else if attachment_upload_form.cdn == 3 {
            headers.insert("Upload-Defer-Length".into(), "1".into());
            headers.insert("Tus-Resumable".into(), "1.0.0".into());
        } else {
            return Err(ServiceError::UnknownCdnVersion(
                attachment_upload_form.cdn,
            ));
        };

        self.get_json_with_headers(
            &attachment_upload_form.signed_upload_location,
            &attachment_upload_form.headers,
        )
        .await
    }

    pub(crate) async fn get_resume_info_cdn3(
        &mut self,
        resumable_url: &str,
        headers: Vec<String>,
    ) -> Result<ResumeInfo, ServiceError> {
        let response: WebSocketResponseMessage = self
            .request(WebSocketRequestMessage {
                verb: Some("HEAD".into()),
                path: Some(resumable_url.to_owned()),
                headers: vec!["Tus-Resumable:1.0.0".into()],
                ..Default::default()
            })
            .await?;

        let upload_offset = response
            .headers()
            .get("Upload-Offset")
            .ok_or(ServiceError::InvalidFrameError {
                reason: "no Upload-Offset header in response".into(),
            })?
            .parse()
            .map_err(|_| ServiceError::InvalidFrameError {
                reason: "invalid integer value for Upload-Offset header".into(),
            })?;

        Ok(ResumeInfo {
            offset: upload_offset,
        })
    }
}
