use std::io::{self, Read};

use futures::TryStreamExt;
use reqwest::{multipart::Part, Method};
use tracing::debug;

use crate::{
    configuration::Endpoint, prelude::AttachmentIdentifier,
    proto::AttachmentPointer, push_service::HttpAuthOverride,
};

use super::{response::ReqwestExt, PushService, ServiceError};

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV2UploadAttributes {
    key: String,
    credential: String,
    acl: String,
    algorithm: String,
    date: String,
    policy: String,
    signature: String,
    // This is different from Java's implementation,
    // and I (Ruben) am unsure why they decide to force-parse at upload-time instead of at registration
    // time.
    attachment_id: u64,
}

impl PushService {
    pub async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let id = match ptr.attachment_identifier.as_ref().unwrap() {
            AttachmentIdentifier::CdnId(id) => &id.to_string(),
            AttachmentIdentifier::CdnKey(key) => key,
        };
        self.get_from_cdn(ptr.cdn_number(), &format!("attachments/{}", id))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let response_stream = self
            .request(
                Method::GET,
                Endpoint::Cdn(cdn_id),
                path,
                HttpAuthOverride::Unidentified, // CDN requests are always without authentication
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .bytes_stream()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            .into_async_read();

        Ok(response_stream)
    }

    pub(crate) async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::Service,
            "/v2/attachments/form/upload",
            HttpAuthOverride::NoOverride,
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    /// Upload attachment to CDN
    ///
    /// Returns attachment ID and the attachment digest
    pub async fn upload_attachment(
        &mut self,
        attrs: AttachmentV2UploadAttributes,
        mut reader: impl Read + Send,
    ) -> Result<(u64, Vec<u8>), ServiceError> {
        let attachment_id = attrs.attachment_id;
        let mut digester =
            crate::digeststream::DigestingReader::new(&mut reader);

        self.post_to_cdn0("attachments/", attrs, "file".into(), &mut digester)
            .await?;

        Ok((attachment_id, digester.finalize()))
    }

    #[tracing::instrument(skip(self, upload_attributes, reader))]
    pub async fn post_to_cdn0(
        &mut self,
        path: &str,
        upload_attributes: AttachmentV2UploadAttributes,
        filename: String,
        mut reader: impl Read + Send,
    ) -> Result<(), ServiceError> {
        // Amazon S3 expects multipart fields in a very specific order (the file contents should go last.)
        let mut form = reqwest::multipart::Form::new();
        form = form.text("acl", upload_attributes.acl);
        form = form.text("key", upload_attributes.key);
        form = form.text("policy", upload_attributes.policy);
        form = form.text("x-amz-algorithm", upload_attributes.algorithm);
        form = form.text("x-amz-credential", upload_attributes.credential);
        form = form.text("x-amz-date", upload_attributes.date);
        form = form.text("x-amz-signature", upload_attributes.signature);

        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .expect("infallible Read instance");

        form = form.text("Content-Type", "application/octet-stream");
        form = form.text("Content-Length", buf.len().to_string());
        form = form.part("file", Part::bytes(buf).file_name(filename));

        let response = self
            .request(
                Method::POST,
                Endpoint::Cdn(0),
                path,
                HttpAuthOverride::NoOverride,
            )?
            .multipart(form)
            .send()
            .await?
            .service_error_for_status()
            .await?;

        debug!("HyperPushService::PUT response: {:?}", response);

        Ok(())
    }
}
