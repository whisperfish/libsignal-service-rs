use std::io::{self, Read};

use bytes::Bytes;
use futures::{FutureExt, StreamExt, TryStreamExt};
use http_body_util::BodyExt;
use hyper::Method;
use tracing::debug;

use crate::{
    configuration::Endpoint,
    prelude::AttachmentIdentifier,
    proto::AttachmentPointer,
    push_service::{HttpAuthOverride, RequestBody},
};

use super::{PushService, ServiceError};

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
    #[tracing::instrument(skip(self))]
    pub(crate) async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let response = self
            .request(
                Method::GET,
                Endpoint::Cdn(cdn_id),
                path,
                &[],
                HttpAuthOverride::Unidentified, // CDN requests are always without authentication
                None,
            )
            .await?;

        Ok(Box::new(
            response
                .into_body()
                .into_data_stream()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                .into_async_read(),
        ))
    }

    pub async fn get_attachment_by_id(
        &mut self,
        id: &str,
        cdn_id: u32,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = format!("attachments/{}", id);
        self.get_from_cdn(cdn_id, &path).await
    }

    pub async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        match ptr.attachment_identifier.as_ref().unwrap() {
            AttachmentIdentifier::CdnId(id) => {
                // cdn_number did not exist for this part of the protocol.
                // cdn_number(), however, returns 0 when the field does not
                // exist.
                self.get_attachment_by_id(&format!("{}", id), ptr.cdn_number())
                    .await
            },
            AttachmentIdentifier::CdnKey(key) => {
                self.get_attachment_by_id(key, ptr.cdn_number()).await
            },
        }
    }

    pub async fn get_attachment_v2_upload_attributes(
        &mut self,
    ) -> Result<AttachmentV2UploadAttributes, ServiceError> {
        self.get_json(
            Endpoint::Service,
            "/v2/attachments/form/upload",
            &[],
            HttpAuthOverride::NoOverride,
        )
        .await
    }

    /// Upload attachment to CDN
    ///
    /// Returns attachment ID and the attachment digest
    pub async fn upload_attachment<'s, C>(
        &mut self,
        attrs: &AttachmentV2UploadAttributes,
        content: &'s mut C,
    ) -> Result<(u64, Vec<u8>), ServiceError>
    where
        C: std::io::Read + Send + 's,
    {
        let values = [
            ("acl", &attrs.acl as &str),
            ("key", &attrs.key),
            ("policy", &attrs.policy),
            ("Content-Type", "application/octet-stream"),
            ("x-amz-algorithm", &attrs.algorithm),
            ("x-amz-credential", &attrs.credential),
            ("x-amz-date", &attrs.date),
            ("x-amz-signature", &attrs.signature),
        ];

        let mut digester = crate::digeststream::DigestingReader::new(content);

        self.post_to_cdn0(
            "attachments/",
            &values,
            Some(("file", &mut digester)),
        )
        .await?;
        Ok((attrs.attachment_id, digester.finalize()))
    }

    #[tracing::instrument(skip(self, value, file), fields(file = file.as_ref().map(|_| "")))]
    pub async fn post_to_cdn0<'s, C>(
        &mut self,
        path: &str,
        value: &[(&str, &str)],
        file: Option<(&str, &'s mut C)>,
    ) -> Result<(), ServiceError>
    where
        C: Read + Send + 's,
    {
        let mut form = mpart_async::client::MultipartRequest::default();

        // mpart-async has a peculiar ordering of the form items,
        // and Amazon S3 expects them in a very specific order (i.e., the file contents should
        // go last.
        //
        // mpart-async uses a VecDeque internally for ordering the fields in the order given.
        //
        // https://github.com/cetra3/mpart-async/issues/16

        for &(k, v) in value {
            form.add_field(k, v);
        }

        if let Some((filename, file)) = file {
            // XXX Actix doesn't cope with none-'static lifetimes
            // https://docs.rs/actix-web/3.2.0/actix_web/body/enum.Body.html
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .expect("infallible Read instance");
            form.add_stream(
                "file",
                filename,
                "application/octet-stream",
                futures::future::ok::<_, ()>(Bytes::from(buf)).into_stream(),
            );
        }

        let content_type =
            format!("multipart/form-data; boundary={}", form.get_boundary());

        // XXX Amazon S3 needs the Content-Length, but we don't know it without depleting the whole
        // stream. Sadly, Content-Length != contents.len(), but should include the whole form.
        let mut body_contents = vec![];
        while let Some(b) = form.next().await {
            // Unwrap, because no error type was used above
            body_contents.extend(b.unwrap());
        }
        tracing::trace!(
            "Sending PUT with Content-Type={} and length {}",
            content_type,
            body_contents.len()
        );

        let response = self
            .request(
                Method::POST,
                Endpoint::Cdn(0),
                path,
                &[],
                HttpAuthOverride::NoOverride,
                Some(RequestBody {
                    contents: body_contents,
                    content_type,
                }),
            )
            .await?;

        debug!("HyperPushService::PUT response: {:?}", response);

        Ok(())
    }
}
