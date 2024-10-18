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
        let path = match ptr.attachment_identifier.as_ref() {
            Some(AttachmentIdentifier::CdnId(id)) => {
                format!("attachments/{}", id)
            },
            Some(AttachmentIdentifier::CdnKey(key)) => {
                format!("attachments/{}", key)
            },
            None => {
                return Err(ServiceError::InvalidFrame {
                    reason: "no attachment identifier in pointer",
                });
            },
        };
        self.get_from_cdn(ptr.cdn_number(), &path).await
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
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .expect("infallible Read instance");

        // Amazon S3 expects multipart fields in a very specific order
        // DO NOT CHANGE THIS (or do it, but feel the wrath of the gods)
        let form = reqwest::multipart::Form::new()
            .text("acl", upload_attributes.acl)
            .text("key", upload_attributes.key)
            .text("policy", upload_attributes.policy)
            .text("Content-Type", "application/octet-stream")
            .text("x-amz-algorithm", upload_attributes.algorithm)
            .text("x-amz-credential", upload_attributes.credential)
            .text("x-amz-date", upload_attributes.date)
            .text("x-amz-signature", upload_attributes.signature)
            .part(
                "file",
                Part::stream(buf)
                    .mime_str("application/octet-stream")?
                    .file_name(filename),
            );

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
