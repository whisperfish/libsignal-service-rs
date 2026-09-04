use std::{collections::HashSet, time::SystemTime};

use chrono::prelude::*;
use libsignal_core::{curve::CurveError, InvalidDeviceId};
use libsignal_protocol::{
    create_sender_key_distribution_message, process_prekey_bundle,
    sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt,
    Aci, CiphertextMessageType, ContentHint, DeviceId, IdentityKey,
    IdentityKeyPair, Pni, ProtocolAddress, ProtocolStore, SenderCertificate,
    SenderKeyStore, ServiceId, SessionNotFound, SessionRecord,
    SignalProtocolError, UnidentifiedSenderMessageContent,
};
use rand::{rng, CryptoRng, Rng};
use tracing::{debug, error, info, trace, warn};
use tracing_futures::Instrument;
use uuid::Uuid;
use zkgroup::{groups::GroupSendFullToken, GROUP_IDENTIFIER_LEN};

use crate::{
    cipher::{get_preferred_protocol_address, ServiceCipher},
    content::ContentBody,
    proto::{
        attachment_pointer::{
            AttachmentIdentifier, Flags as AttachmentPointerFlags,
        },
        sync_message::{
            self, message_request_response, MessageRequestResponse,
        },
        AttachmentPointer, SyncMessage,
    },
    push_service::*,
    sender_key_store_ext::SenderKeyStoreExt,
    service_address::ServiceIdExt,
    session_store::SessionStoreExt,
    unidentified_access::{
        CombinedUnidentifiedSenderAccessKeys, UnidentifiedAccess,
    },
    utils::{serde_device_id, serde_service_id, BASE64_RELAXED},
    websocket::{self, SignalWebSocket},
};

pub use crate::proto::ContactDetails;

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPushMessage {
    pub r#type: u32,
    #[serde(with = "serde_device_id")]
    pub destination_device_id: DeviceId,
    pub destination_registration_id: u32,
    pub content: String,
}

#[derive(serde::Serialize, Debug)]
pub struct OutgoingPushMessages {
    #[serde(with = "serde_service_id")]
    pub destination: ServiceId,
    pub timestamp: u64,
    pub messages: Vec<OutgoingPushMessage>,
    pub online: bool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResponse {
    pub needs_sync: bool,
}

pub type SendMessageResult = Result<SentMessage, MessageSenderError>;

#[derive(Debug, Clone)]
pub struct SentMessage {
    pub recipient: ServiceId,
    pub used_identity_key: IdentityKey,
    pub unidentified: bool,
    pub needs_sync: bool,
}

/// Authorization for `PUT /v1/messages/multi_recipient`.
///
/// For non-story multi-recipient sends Signal requires **exactly one** of:
/// - a combined unidentified-access key (the bitwise XOR of every
///   recipient's 16-byte UAK), sent base64-encoded in the
///   `Unidentified-Access-Key` header, or
/// - a group-send endorsement full token, sent base64-encoded in the
///   `Group-Send-Token` header.
///
/// Stories carry neither header; pass `None` for `access` in
/// [`MultiRecipientMessagesRequest`] when `story` is `true`.
#[derive(Clone)]
pub enum MultiRecipientAccess {
    /// Combined unidentified-access keys.
    UnidentifiedAccessKey(CombinedUnidentifiedSenderAccessKeys),
    /// A group-send endorsement token covering the recipients.
    GroupSendToken(GroupSendFullToken),
}

impl MultiRecipientAccess {
    /// `(header name, base64-encoded value)` for the access strategy.
    pub(crate) fn header(&self) -> (&'static str, String) {
        use base64::Engine;
        match self {
            MultiRecipientAccess::UnidentifiedAccessKey(keys) => {
                ("Unidentified-Access-Key", BASE64_RELAXED.encode(keys.0))
            },
            MultiRecipientAccess::GroupSendToken(token) => (
                "Group-Send-Token",
                BASE64_RELAXED.encode(zkgroup::serialize(token)),
            ),
        }
    }
}

/// Request to `PUT /v1/messages/multi_recipient`.
///
/// `payload` is the raw Sealed Sender v2 multi-recipient message produced by
/// `libsignal_protocol::sealed_sender_multi_recipient_encrypt`.
///
/// `timestamp`/`online`/`urgent`/`story` mirror the server's query parameters.
pub struct MultiRecipientMessagesRequest<'a> {
    /// Sender's timestamp for the envelope.
    pub timestamp: u64,
    /// Deliver only to recipients that are online when the message is sent.
    pub online: bool,
    /// Whether the message should trigger push notifications.
    pub urgent: bool,
    /// Story message: access tokens are not checked and sending to
    /// nonexistent recipients is permitted.
    pub story: bool,
    /// Raw Sealed Sender v2 multi-recipient payload
    /// (`application/vnd.signal-messenger.mrm`).
    pub payload: &'a [u8],
    /// `None` for stories; otherwise [`MultiRecipientAccess::UnidentifiedAccessKey`]
    /// xor [`MultiRecipientAccess::GroupSendToken`].
    pub access: Option<MultiRecipientAccess>,
}

/// Attachment specification to be used for uploading.
///
/// Loose equivalent of Java's `SignalServiceAttachmentStream`.
#[derive(Debug, Default)]
pub struct AttachmentSpec {
    pub content_type: String,
    pub length: usize,
    pub file_name: Option<String>,
    pub preview: Option<Vec<u8>>,
    pub voice_note: Option<bool>,
    pub borderless: Option<bool>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub caption: Option<String>,
    pub blur_hash: Option<String>,
}

#[derive(Clone)]
pub struct MessageSender<S> {
    identified_ws: SignalWebSocket<websocket::Identified>,
    unidentified_ws: SignalWebSocket<websocket::Unidentified>,
    service: PushService,
    cipher: ServiceCipher<S>,
    protocol_store: S,
    local_aci: Aci,
    local_pni: Pni,
    aci_identity: IdentityKeyPair,
    pni_identity: Option<IdentityKeyPair>,
    device_id: DeviceId,
}

#[derive(thiserror::Error, Debug)]
pub enum AttachmentUploadError {
    #[error("{0}")]
    ServiceError(#[from] ServiceError),

    #[error("Could not read attachment contents")]
    IoError(#[from] std::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum MessageSenderError {
    #[error("service error: {0}")]
    ServiceError(#[from] ServiceError),

    #[error("protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),

    #[error("invalid private key: {0}")]
    InvalidPrivateKey(#[from] CurveError),

    #[error("invalid device ID: {0}")]
    InvalidDeviceId(#[from] InvalidDeviceId),

    #[error("Failed to upload attachment {0}")]
    AttachmentUploadError(#[from] AttachmentUploadError),

    #[error("primary device can't send sync message {0:?}")]
    SendSyncMessageError(sync_message::request::Type),

    #[error("Untrusted identity key with {address:?}")]
    UntrustedIdentity { address: ServiceId },

    #[error("Exceeded maximum number of retries")]
    MaximumRetriesLimitExceeded,

    #[error("Proof of type {options:?} required using token {token}")]
    ProofRequired { token: String, options: Vec<String> },

    #[error("Recipient not found: {service_id:?}")]
    NotFound { service_id: ServiceId },

    #[error("no messages were encrypted: this should not really happen and most likely implies a logic error")]
    NoMessagesToSend,
}

pub type GroupV2Id = [u8; GROUP_IDENTIFIER_LEN];

#[derive(Debug)]
pub enum ThreadIdentifier {
    Aci(Uuid),
    Group(GroupV2Id),
}

#[derive(Debug)]
pub struct EncryptedMessages {
    messages: Vec<OutgoingPushMessage>,
}

/// Outcome of attempting to recover from a send error: retry the loop, or
/// give up and propagate.
enum SendRecovery {
    Retry,
    Terminal(MessageSenderError),
}

impl<S> MessageSender<S>
where
    S: ProtocolStore
        + SenderKeyStore
        + SenderKeyStoreExt
        + SessionStoreExt
        + Sync
        + Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identified_ws: SignalWebSocket<websocket::Identified>,
        unidentified_ws: SignalWebSocket<websocket::Unidentified>,
        service: PushService,
        cipher: ServiceCipher<S>,
        protocol_store: S,
        local_aci: impl Into<Aci>,
        local_pni: impl Into<Pni>,
        aci_identity: IdentityKeyPair,
        pni_identity: Option<IdentityKeyPair>,
        device_id: DeviceId,
    ) -> Self {
        MessageSender {
            service,
            identified_ws,
            unidentified_ws,
            cipher,
            protocol_store,
            local_aci: local_aci.into(),
            local_pni: local_pni.into(),
            aci_identity,
            pni_identity,
            device_id,
        }
    }

    /// Encrypts and uploads an attachment
    ///
    /// Contents are accepted as an owned, plain text Vec, because encryption happens in-place.
    #[tracing::instrument(skip(self, contents, csprng), fields(size = contents.len()))]
    pub async fn upload_attachment<R: Rng + CryptoRng>(
        &mut self,
        spec: AttachmentSpec,
        mut contents: Vec<u8>,
        csprng: &mut R,
    ) -> Result<AttachmentPointer, AttachmentUploadError> {
        let len = contents.len();
        // Encrypt
        let (key, iv) = {
            let mut key = [0u8; 64];
            let mut iv = [0u8; 16];
            csprng.fill_bytes(&mut key);
            csprng.fill_bytes(&mut iv);
            (key, iv)
        };

        // Padded length uses an exponential bracketting thingy.
        // If you want to see how it looks:
        // https://www.wolframalpha.com/input/?i=plot+floor%281.05%5Eceil%28log_1.05%28x%29%29%29+for+x+from+0+to+5000000
        let padded_len: usize = {
            // Java:
            // return (int) Math.max(541, Math.floor(Math.pow(1.05, Math.ceil(Math.log(size) / Math.log(1.05)))))
            std::cmp::max(
                541,
                1.05f64.powf((len as f64).log(1.05).ceil()).floor() as usize,
            )
        };
        if padded_len < len {
            error!(
                "Padded len {} < len {}. Continuing with a privacy risk.",
                padded_len, len
            );
        } else {
            contents.resize(padded_len, 0);
        }

        tracing::trace_span!("encrypting attachment").in_scope(|| {
            crate::attachment_cipher::encrypt_in_place(iv, key, &mut contents)
        });

        // Request upload attributes
        // TODO: we can actually store the upload spec to be able to resume the upload later
        // if it fails or stalls (= we should at least split the API calls so clients can decide what to do)
        let attachment_upload_form = self
            .service
            .get_attachment_v4_upload_attributes()
            .instrument(tracing::trace_span!("requesting upload attributes"))
            .await?;

        let resumable_upload_url = self
            .service
            .get_attachment_resumable_upload_url(&attachment_upload_form)
            .await?;

        let attachment_digest = self
            .service
            .upload_attachment_v4(
                attachment_upload_form.cdn,
                &resumable_upload_url,
                contents.len() as u64,
                attachment_upload_form.headers,
                &mut std::io::Cursor::new(&contents),
            )
            .await?;

        Ok(AttachmentPointer {
            content_type: Some(spec.content_type),
            key: Some(key.to_vec()),
            size: Some(len as u32),
            // thumbnail: Option<Vec<u8>>,
            digest: Some(attachment_digest.digest),
            file_name: spec.file_name,
            flags: Some(
                if spec.voice_note == Some(true) {
                    AttachmentPointerFlags::VoiceMessage as u32
                } else {
                    0
                } | if spec.borderless == Some(true) {
                    AttachmentPointerFlags::Borderless as u32
                } else {
                    0
                },
            ),
            width: spec.width,
            height: spec.height,
            caption: spec.caption,
            blur_hash: spec.blur_hash,
            upload_timestamp: Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("unix epoch in the past")
                    .as_millis() as u64,
            ),
            cdn_number: Some(attachment_upload_form.cdn),
            attachment_identifier: Some(AttachmentIdentifier::CdnKey(
                attachment_upload_form.key,
            )),
            ..Default::default()
        })
    }

    /// Upload contact details to the CDN
    ///
    /// Returns attachment ID and the attachment digest
    #[tracing::instrument(skip(self, contacts))]
    async fn upload_contact_details<Contacts>(
        &mut self,
        contacts: Contacts,
    ) -> Result<AttachmentPointer, AttachmentUploadError>
    where
        Contacts: IntoIterator<Item = ContactDetails>,
    {
        use prost::Message;
        let mut out = Vec::new();
        for contact in contacts {
            contact
                .encode_length_delimited(&mut out)
                .expect("infallible encoding");
            // XXX add avatar here
        }

        let spec = AttachmentSpec {
            content_type: "application/octet-stream".into(),
            length: out.len(),
            file_name: None,
            preview: None,
            voice_note: None,
            borderless: None,
            width: None,
            height: None,
            caption: None,
            blur_hash: None,
        };
        self.upload_attachment(spec, out, &mut rng()).await
    }

    /// Return whether we have to prepare sync messages for other devices
    ///
    /// - If we are the main registered device, and there are established sub-device sessions (linked clients), return true
    /// - If we are a secondary linked device, return true
    async fn is_multi_device(&self) -> bool {
        if self.device_id == *DEFAULT_DEVICE_ID {
            self.protocol_store
                .get_sub_device_sessions(&self.local_aci.into())
                .await
                .is_ok_and(|s| !s.is_empty())
        } else {
            true
        }
    }

    /// Send a message `content` to a single `recipient`.
    #[tracing::instrument(
        skip(self, unidentified_access, message),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub async fn send_message(
        &mut self,
        recipient: &ServiceId,
        mut unidentified_access: Option<&UnidentifiedAccess>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        include_pni_signature: bool,
        online: bool,
    ) -> SendMessageResult {
        let content_body = message.into();
        let message_to_self = recipient == &self.local_aci;
        let sync_message =
            matches!(content_body, ContentBody::SynchronizeMessage(..));
        let is_multi_device = self.is_multi_device().await;

        // only send a sync message when sending to self and skip the rest of the process
        if message_to_self && is_multi_device && !sync_message {
            debug!("sending note to self");
            if let Some(sync_message) = self
                .create_multi_device_sent_transcript_content(
                    Some(recipient),
                    content_body,
                    timestamp,
                    None,
                )
            {
                return self
                    .try_send_message(
                        *recipient,
                        None,
                        sync_message.into_proto(),
                        timestamp,
                        include_pni_signature,
                        online,
                    )
                    .await;
            } else {
                error!("could not create sync message from message to self");
                return SendMessageResult::Err(
                    MessageSenderError::NoMessagesToSend,
                );
            }
        }

        // sync messages are never sent as unidentified (reasons unclear), see: https://github.com/signalapp/Signal-Android/blob/main/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java#L779
        if sync_message {
            unidentified_access.take();
        }

        // try to send the original message to all the recipient's devices
        let result = self
            .try_send_message(
                *recipient,
                unidentified_access,
                content_body.clone().into_proto(),
                timestamp,
                include_pni_signature,
                online,
            )
            .await;

        let needs_sync = match &result {
            Ok(SentMessage { needs_sync, .. }) => *needs_sync,
            _ => false,
        };

        if needs_sync || is_multi_device {
            let sync_body = if sync_message {
                Some(content_body)
            } else {
                // Only some ContentBody types are syncable to self,
                // not getting a content body to sync is not an error.
                self.create_multi_device_sent_transcript_content(
                    Some(recipient),
                    content_body,
                    timestamp,
                    Some(&result),
                )
            };
            if let Some(body) = sync_body {
                debug!("sending multi-device sync message");
                self.try_send_message(
                    self.local_aci.into(),
                    None,
                    body.into_proto(),
                    timestamp,
                    false,
                    false,
                )
                .await?;
            }
        }

        result
    }

    /// Send a message to the recipients in a group using sender keys.
    ///
    /// Recipients are a list of tuples, each containing:
    /// - The recipient's address
    /// - The recipient's unidentified access
    /// - Whether the recipient requires a PNI signature
    ///
    /// `distribution_id` identifies the sender-key chain for this group. The
    /// caller is responsible for rotation (generate a new UUID on member leave
    /// or safety-number change).
    #[tracing::instrument(
        skip(self, recipients, message),
        fields(recipients = recipients.as_ref().len(), dist_id = %distribution_id),
    )]
    pub async fn send_message_to_group(
        &mut self,
        distribution_id: Uuid,
        recipients: impl AsRef<[(ServiceId, Option<UnidentifiedAccess>, bool)]>,
        message: impl Into<ContentBody>,
        timestamp: u64,
        online: bool,
    ) -> Vec<SendMessageResult> {
        let content_body: ContentBody = message.into();

        // Share SKDMs with any devices that haven't received them yet.
        // XXX Ideally, we *attach* the SKDM to the message-to-be-sent.
        //     This is an ugly hack
        if let Err(e) = self
            .share_sender_key_if_needed(
                distribution_id,
                timestamp,
                recipients.as_ref(),
            )
            .await
        {
            return vec![Err(e)];
        }

        // Encode the content once.
        use prost::Message;
        let content_bytes = content_body.clone().into_proto().encode_to_vec();

        let sender_address = match self
            .local_aci
            .to_protocol_address(self.device_id)
        {
            Ok(addr) => addr,
            Err(e) => return vec![Err(MessageSenderError::InvalidDeviceId(e))],
        };
        // Pad + group-encrypt once for the whole group, inside `cipher.rs` so
        // the send-side padding invariant stays co-located with the receive
        // path's `strip_padding` (`Type::UnidentifiedSender` arm). See D.4.
        let mut rng = rng();
        let skm_serialized = match crate::cipher::encrypt_sender_key_message(
            &mut self.protocol_store,
            &sender_address,
            distribution_id,
            &content_bytes,
            &mut rng,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(e) => return vec![Err(MessageSenderError::ServiceError(e))],
        };

        let recipients_ref = recipients.as_ref();
        // Recipients with unidentified access go through the sealed-sender
        // sender-key paths; the rest fall back to identified 1:1 sends.
        let sealed: Vec<(ServiceId, &UnidentifiedAccess)> = recipients_ref
            .iter()
            .filter_map(|(r, ua, _)| ua.as_ref().map(|a| (*r, a)))
            .collect();

        let mut results: Vec<SendMessageResult> = match self
            .send_sender_key_payload(
                &sealed,
                &skm_serialized,
                timestamp,
                online,
            )
            .await
        {
            Ok(results) => results,
            Err(e) => return vec![Err(e)],
        };

        for (recipient, _, include_pni_signature) in
            recipients_ref.iter().filter(|(_, ua, _)| ua.is_none())
        {
            // Identified 1:1 fallback, which also establishes missing sessions.
            results.push(
                self.try_send_message(
                    *recipient,
                    None,
                    content_body.clone().into_proto(),
                    timestamp,
                    *include_pni_signature,
                    online,
                )
                .await,
            );
        }

        // we only need to send a synchronization message once
        let needs_sync = results.iter().any(|r| {
            matches!(
                r,
                Ok(SentMessage {
                    needs_sync: true,
                    ..
                })
            )
        });
        self.send_group_sent_transcript(
            &content_body,
            timestamp,
            &results,
            needs_sync,
        )
        .await;

        results
    }

    /// Send a sender-key retry receipt
    ///
    /// The receipt goes out as a regular encrypted (or sealed-sender encrypted,
    /// when `unidentified_access` is supplied) `Content`, so it rides the same
    /// fan-out, session repair, and retry machinery as any other message.
    ///
    /// Divergences from the official clients:
    /// - Official clients deliver retry receipts as unencrypted `PlaintextContent`;
    ///   receiving clients accept the DEM inside an encrypted `Content` too.
    /// - Under sealed sender they use `ContentHint::Implicit` and attach the
    ///   group id; our sealed path hardcodes `ContentHint::Default` without a
    ///   group id (see `sealed_sender_encrypt`).  Harmless in practice: the
    ///   receipt's original sender finds its send-log entry by timestamp.
    #[tracing::instrument(
        skip(self, unidentified_access),
        fields(recipient = recipient.service_id_string(), unidentified_send = unidentified_access.is_some(), failed_timestamp),
    )]
    pub async fn send_sender_key_decryption_error_message(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<&UnidentifiedAccess>,
        failed_timestamp: u64,
        failed_device: DeviceId,
    ) -> Result<(), MessageSenderError> {
        info!("sending retry receipt/decryption error");

        // The absent `ratchet_key` marks this as a sender-key failure.
        // This function assumes the 1:1 session is intact, and hence tries to
        // transmit the DME through the 1:1 encrypted (sealed, if available) channel.
        //
        // A DME for a 1:1 decrypt failure carries `ratchet_key`
        // and must be deliverable *without* depending on the session under
        // repair; upstream sends those as unencrypted `PlaintextContent`
        // (or sealed USMC) envelopes.  Implement that case as a sibling
        // function producing plaintext envelopes over this same fan-out.
        let content_body = ContentBody::DecryptionErrorMessage(
            crate::proto::DecryptionErrorMessage {
                ratchet_key: None,
                timestamp: Some(failed_timestamp),
                device_id: Some(failed_device.into()),
            },
        );

        self.try_send_message(
            *recipient,
            unidentified_access,
            content_body.into_proto(),
            Utc::now().timestamp_millis() as u64,
            false,
            false,
        )
        .await?;

        Ok(())
    }

    /// Sealed-sender half of [`send_message_to_group`]: send the group's
    /// `SenderKeyMessage` (wrapped in one shared `usmc`) to the recipients
    /// that have unidentified access, through a single multi-recipient
    /// request when every recipient has sessions for all devices, and
    /// per-recipient sealed sends otherwise.
    async fn send_sender_key_payload(
        &mut self,
        recipients: &[(ServiceId, &UnidentifiedAccess)],
        skm_serialized: &[u8],
        timestamp: u64,
        online: bool,
    ) -> Result<Vec<SendMessageResult>, MessageSenderError> {
        if recipients.is_empty() {
            return Ok(vec![]);
        }

        // The USMC depends only on the SKM and our certificate, not on the
        // recipient; build it once and share it across both send paths below.
        let usmc = Self::build_group_usmc(
            &recipients[0].1.certificate,
            skm_serialized,
        )?;

        let mut results = vec![];

        // Recipients with a session for every enumerated device go through
        // the single multi-recipient request; the rest fall back to
        // per-recipient sends (which also establish missing sessions). A
        // store error during the check degrades to the fallback, where it
        // surfaces as a proper per-recipient error.
        let mut mrm_recipients: Vec<(ServiceId, &UnidentifiedAccess)> = vec![];
        let mut skr_recipients: Vec<(ServiceId, &UnidentifiedAccess)> = vec![];
        for (recipient, unidentified_access) in recipients {
            let all_sessions = self
                .collect_recipient_sessions(*recipient)
                .await
                .is_ok_and(|s| s.is_some());
            if all_sessions {
                mrm_recipients.push((*recipient, unidentified_access));
            } else {
                skr_recipients.push((*recipient, unidentified_access));
            }
        }

        if !mrm_recipients.is_empty() {
            match self
                .send_message_to_group_multi_recipient(
                    &mrm_recipients,
                    &usmc,
                    timestamp,
                    online,
                )
                .await
            {
                Ok(mrm_results) => results.extend(mrm_results),
                Err(e) => {
                    tracing::warn!(
                        %e,
                        "multi-recipient send failed; falling back to 1:1"
                    );
                    skr_recipients.append(&mut mrm_recipients);
                },
            }
        }

        for (recipient, unidentified_access) in skr_recipients {
            results.push(
                self.send_sender_key_to_recipient(
                    recipient,
                    unidentified_access,
                    &usmc,
                    timestamp,
                    online,
                )
                .await,
            );
        }

        Ok(results)
    }

    /// Send the multi-device `Sent` transcript for a group send: when the
    /// server requested a sync or we are multi-device, mirror the results as
    /// a `Sent` `SyncMessage` to our own devices. Transcript-send failures
    /// are logged, not propagated: the group message itself was delivered.
    async fn send_group_sent_transcript(
        &mut self,
        content_body: &ContentBody,
        timestamp: u64,
        results: &[SendMessageResult],
        needs_sync: bool,
    ) {
        if !(needs_sync || self.is_multi_device().await) {
            return;
        }

        let Some(sync_message) = self
            .create_multi_device_sent_transcript_content(
                None,
                content_body.clone(),
                timestamp,
                results,
            )
        else {
            error!("could not create sync message from a group message");
            return;
        };
        // Note: the result of sending a sync message is not included in results
        // See Signal Android `SignalServiceMessageSender.java:2817`
        if let Err(error) = self
            .try_send_message(
                self.local_aci.into(),
                None,
                sync_message.into_proto(),
                timestamp,
                false, // XXX: maybe the sync device does want a PNI signature?
                false,
            )
            .await
        {
            error!(%error, "failed to send a synchronization message");
        }
    }

    /// Repair sessions with a recipient's devices after a server-reported
    /// device mismatch (`MismatchedDevicesException`/`StaleDevices`): drop
    /// sessions for devices the server does not expect (`extra_devices`)
    /// and establish sessions with devices we did not know about
    /// (`missing_devices`), so the caller can rebuild and retry the send.
    async fn repair_recipient_sessions(
        &mut self,
        recipient: ServiceId,
        extra_devices: &[DeviceId],
        missing_devices: &[DeviceId],
    ) -> Result<(), MessageSenderError> {
        for device_id in extra_devices {
            tracing::debug!("dropping session with device {}", device_id);
            self.protocol_store
                .delete_service_addr_device_session(
                    &recipient.to_protocol_address(*device_id)?,
                )
                .await?;
        }

        let mut rng = rng();

        for device_id in missing_devices {
            tracing::debug!(
                "creating session with missing device {}",
                device_id
            );
            let remote_address = recipient.to_protocol_address(*device_id)?;
            let pre_key = self
                .identified_ws
                .get_pre_key(&recipient, *device_id)
                .await?;

            process_prekey_bundle(
                &remote_address,
                &self
                    .local_aci
                    .to_protocol_address(self.device_id)
                    .expect("valid device id"),
                &mut self.protocol_store.clone(),
                &mut self.protocol_store,
                &pre_key,
                SystemTime::now(),
                &mut rng,
            )
            .await
            .map_err(|e| {
                error!(%e, ?recipient, "failed to create session");
                MessageSenderError::UntrustedIdentity { address: recipient }
            })?;
        }

        Ok(())
    }

    /// Handle the `Err` arm of a websocket send, shared by the sender-key and
    /// 1:1 send retry loops. Performs session bookkeeping for
    /// `MismatchedDevicesException`/`StaleDevices` so the caller can rebuild and
    /// retry; all other errors are terminal.
    async fn recover_from_send_error(
        &mut self,
        recipient: ServiceId,
        err: ServiceError,
    ) -> Result<SendRecovery, MessageSenderError> {
        match err {
            ServiceError::MismatchedDevicesException(ref m) => {
                tracing::debug!("{:?}", m);
                self.repair_recipient_sessions(
                    recipient,
                    &m.extra_devices,
                    &m.missing_devices,
                )
                .await?;
                Ok(SendRecovery::Retry)
            },
            ServiceError::StaleDevices(ref m) => {
                tracing::debug!("{:?}", m);
                self.repair_recipient_sessions(
                    recipient,
                    &m.stale_devices,
                    &[],
                )
                .await?;
                Ok(SendRecovery::Retry)
            },
            ServiceError::ProofRequiredError(ref p) => {
                tracing::debug!("{:?}", p);
                Ok(SendRecovery::Terminal(MessageSenderError::ProofRequired {
                    token: p.token.clone(),
                    options: p.options.clone(),
                }))
            },
            ServiceError::NotFoundError => {
                tracing::debug!("Not found when sending a message");
                Ok(SendRecovery::Terminal(MessageSenderError::NotFound {
                    service_id: recipient,
                }))
            },
            e => {
                tracing::debug!(
                    "Default error handler for ws.send_messages: {}",
                    e
                );
                Ok(SendRecovery::Terminal(MessageSenderError::ServiceError(e)))
            },
        }
    }

    /// Multi-recipient counterpart of [`recover_from_send_error`] for
    /// `PUT /v1/messages/multi_recipient`, whose `409`/`410` carry per-account
    /// device lists ([`MultiRecipientMismatchedDevices`] /
    /// [`MultiRecipientStaleDevices`]).
    ///
    /// Deletes extra/stale sessions and establishes sessions for missing
    /// devices across all reported accounts, so the caller can re-gather
    /// sessions and retry the whole encrypt+send. Other errors are terminal;
    /// per-recipient 404s arrive in the 200 body (`uuids404`), not here.
    async fn recover_from_multi_recipient_send_error(
        &mut self,
        err: ServiceError,
    ) -> Result<SendRecovery, MessageSenderError> {
        match err {
            ServiceError::MultiRecipientMismatchedDevices(accounts) => {
                for account in &accounts {
                    tracing::debug!(
                        ?account.uuid,
                        extra = ?account.devices.extra_devices,
                        missing = ?account.devices.missing_devices,
                        "multi-recipient mismatched devices",
                    );
                    self.repair_recipient_sessions(
                        account.uuid,
                        &account.devices.extra_devices,
                        &account.devices.missing_devices,
                    )
                    .await?;
                }
                Ok(SendRecovery::Retry)
            },
            ServiceError::MultiRecipientStaleDevices(accounts) => {
                for account in &accounts {
                    tracing::debug!(
                        ?account.uuid,
                        stale = ?account.devices.stale_devices,
                        "multi-recipient stale devices",
                    );
                    self.repair_recipient_sessions(
                        account.uuid,
                        &account.devices.stale_devices,
                        &[],
                    )
                    .await?;
                }
                Ok(SendRecovery::Retry)
            },
            ServiceError::ProofRequiredError(ref p) => {
                tracing::debug!("multi-recipient proof required: {:?}", p);
                Ok(SendRecovery::Terminal(MessageSenderError::ProofRequired {
                    token: p.token.clone(),
                    options: p.options.clone(),
                }))
            },
            e => {
                tracing::debug!(
                    "Default error handler for multi-recipient send: {}",
                    e
                );
                Ok(SendRecovery::Terminal(MessageSenderError::ServiceError(e)))
            },
        }
    }

    /// Dispatch a built `OutgoingPushMessages` to the websocket, via the
    /// unidentified channel when `unidentified_access` is supplied, else the
    /// identified channel.
    async fn dispatch_outgoing(
        &mut self,
        messages: OutgoingPushMessages,
        unidentified_access: Option<&UnidentifiedAccess>,
    ) -> Result<SendMessageResponse, ServiceError> {
        if let Some(unidentified) = unidentified_access {
            tracing::debug!("sending via unidentified");
            self.unidentified_ws
                .send_messages_unidentified(messages, unidentified)
                .await
        } else {
            tracing::debug!("sending identified");
            self.identified_ws.send_messages(messages).await
        }
    }

    /// Build the `SentMessage` result after a successful dispatch, looking up
    /// the recipient's identity key on the default device.
    async fn build_sent_message(
        &mut self,
        recipient: ServiceId,
        unidentified: bool,
        needs_sync: bool,
    ) -> Result<SentMessage, MessageSenderError> {
        let used_identity_key = self
            .protocol_store
            .get_identity(&recipient.to_protocol_address(*DEFAULT_DEVICE_ID)?)
            .await?
            .ok_or(MessageSenderError::UntrustedIdentity {
                address: recipient,
            })?;
        Ok(SentMessage {
            recipient,
            used_identity_key,
            unidentified,
            needs_sync,
        })
    }

    /// Send the sender-key payload (pre-wrapped in `usmc`) to a single
    /// recipient, sealed-sender encrypted per device, with the full retry
    /// loop.
    async fn send_sender_key_to_recipient(
        &mut self,
        recipient: ServiceId,
        unidentified_access: &UnidentifiedAccess,
        usmc: &UnidentifiedSenderMessageContent,
        timestamp: u64,
        online: bool,
    ) -> SendMessageResult {
        use base64::Engine;

        self.send_with_retries(
            recipient,
            Some(unidentified_access),
            timestamp,
            online,
            // Sender-key payloads ride the unidentified (sealed-sender)
            // channel only; there is no identified fallback for them.
            false,
            async |sender, _certificate| {
                let devices = sender
                    .enumerate_recipient_devices(&recipient)
                    .await?;

                let mut recipient_messages = vec![];
                for &device_id in &devices {
                    let dest_address =
                        match recipient.to_protocol_address(device_id) {
                            Ok(addr) => addr,
                            Err(_) => continue,
                        };

                    let session_record = sender
                        .protocol_store
                        .load_session(&dest_address)
                        .await?;
                    let session_record = match session_record {
                        Some(s) => s,
                        None => {
                            tracing::debug!(
                                "no session for {dest_address}; skipping sender-key send"
                            );
                            continue;
                        },
                    };

                    let registration_id =
                        match session_record.remote_registration_id() {
                            Ok(id) => id,
                            Err(e) => {
                                tracing::debug!(%e, "failed to get registration id for {dest_address}");
                                continue;
                            },
                        };

                    let mut rng = rng();
                    let sealed_bytes =
                        match sealed_sender_encrypt_from_usmc(
                            &dest_address,
                            usmc,
                            &sender.protocol_store,
                            &mut rng,
                        )
                        .await
                        {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::debug!(%e, "failed to sealed-sender-encrypt for {dest_address}");
                                continue;
                            },
                        };

                    use crate::proto::envelope::Type;
                    recipient_messages.push(OutgoingPushMessage {
                        r#type: Type::UnidentifiedSender as u32,
                        destination_device_id: device_id,
                        destination_registration_id: registration_id,
                        content: BASE64_RELAXED.encode(sealed_bytes),
                    });
                }

                if recipient_messages.is_empty() {
                    return Err(MessageSenderError::NoMessagesToSend);
                }
                Ok(recipient_messages)
            },
        )
        .await
    }

    /// Send the messages built by `make_messages` to a single recipient,
    /// retrying up to 4 times on recoverable errors (`recover_from_send_error`
    /// repairs server-reported device discrepancies and retries).
    /// `make_messages` runs on every attempt because recovery may change the
    /// session set.
    ///
    /// When `allow_unidentified_downgrade` is set and the send fails with
    /// `Unauthorized`, the send is retried over the identified channel; the
    /// builder's certificate argument then reads `None`.
    async fn send_with_retries(
        &mut self,
        recipient: ServiceId,
        mut unidentified_access: Option<&UnidentifiedAccess>,
        timestamp: u64,
        online: bool,
        allow_unidentified_downgrade: bool,
        mut make_messages: impl AsyncFnMut(
            &mut Self,
            Option<&SenderCertificate>,
        ) -> Result<
            Vec<OutgoingPushMessage>,
            MessageSenderError,
        >,
    ) -> SendMessageResult {
        for _ in 0..4u8 {
            let messages = make_messages(
                self,
                unidentified_access.map(|x| &x.certificate),
            )
            .await?;
            let messages = OutgoingPushMessages {
                destination: recipient,
                timestamp,
                messages,
                online,
            };

            match self.dispatch_outgoing(messages, unidentified_access).await {
                Ok(SendMessageResponse { needs_sync }) => {
                    tracing::debug!("message sent!");
                    return self
                        .build_sent_message(
                            recipient,
                            unidentified_access.is_some(),
                            needs_sync,
                        )
                        .await;
                },
                Err(ServiceError::Unauthorized)
                    if allow_unidentified_downgrade
                        && unidentified_access.is_some() =>
                {
                    tracing::trace!("unauthorized error using unidentified; retry over identified");
                    unidentified_access = None;
                },
                Err(e) => {
                    match self.recover_from_send_error(recipient, e).await? {
                        SendRecovery::Retry => {},
                        SendRecovery::Terminal(err) => return Err(err),
                    }
                },
            }
        }

        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    /// Wrap a serialized `SenderKeyMessage` in a `Resendable`-hinted
    /// `UnidentifiedSenderMessageContent` signed by `certificate`.
    ///
    /// The USMC depends only on the SKM and the sender certificate, so one is
    /// shared across all recipients of a send.
    fn build_group_usmc(
        certificate: &SenderCertificate,
        skm_serialized: &[u8],
    ) -> Result<UnidentifiedSenderMessageContent, MessageSenderError> {
        UnidentifiedSenderMessageContent::new(
            CiphertextMessageType::SenderKey,
            certificate.clone(),
            skm_serialized.to_vec(),
            ContentHint::Resendable,
            None,
        )
        .map_err(MessageSenderError::ProtocolError)
    }

    /// Deliver the sender-key payload to `recipients` via a single
    /// `PUT /v1/messages/multi_recipient` request.
    ///
    /// All recipients must have supplied [`UnidentifiedAccess`] and have
    /// sessions for every enumerated device; recipients without a UAK or with
    /// missing sessions are routed to the 1:1 fallback by the caller.
    ///
    /// Returns `Err` for failures that abort the whole batch (session load,
    /// encryption, terminal send error); the caller falls those
    /// recipients back to the 1:1 path. On success each recipient maps to an
    /// [`SentMessage`], with unregistered recipients (the 200 body's
    /// `uuids404`) surfaced as [`MessageSenderError::NotFound`].
    ///
    /// On `409`/`410` the server reports per-account device deltas, handled by
    /// [`recover_from_multi_recipient_send_error`]; the whole encrypt+send is
    /// retried (matching the per-recipient loops' 4 attempts).
    async fn send_message_to_group_multi_recipient(
        &mut self,
        recipients: &[(ServiceId, &UnidentifiedAccess)],
        usmc: &UnidentifiedSenderMessageContent,
        timestamp: u64,
        online: bool,
    ) -> Result<Vec<SendMessageResult>, MessageSenderError> {
        for _ in 0..4u8 {
            // Gather (address, session) for every enumerated device of every
            // recipient. `enumerate_recipient_devices` excludes the local
            // device; `sealed_sender_multi_recipient_encrypt` requires a
            // session for each destination, so a missing session aborts the
            // multi-recipient path for the whole call (caller falls back to
            // 1:1 for the affected recipients).
            let mut dests: Vec<(ProtocolAddress, SessionRecord)> = vec![];
            for (recipient, _) in recipients {
                match self.collect_recipient_sessions(*recipient).await? {
                    Some(sessions) => dests.extend(sessions),
                    None => {
                        tracing::debug!(
                            ?recipient,
                            "no sessions for all devices; deferring to 1:1 fallback"
                        );
                        return Err(MessageSenderError::NoMessagesToSend);
                    },
                }
            }

            let (dest_addresses, dest_sessions): (Vec<_>, Vec<_>) =
                dests.into_iter().unzip();

            let dest_refs: Vec<&ProtocolAddress> =
                dest_addresses.iter().collect();
            let session_refs: Vec<&SessionRecord> =
                dest_sessions.iter().collect();

            let mut rng = rng();
            let payload = sealed_sender_multi_recipient_encrypt(
                &dest_refs,
                &session_refs,
                std::iter::empty::<ServiceId>(),
                usmc,
                &self.protocol_store,
                &mut rng,
            )
            .await?;

            let keys: Vec<&Vec<u8>> =
                recipients.iter().map(|(_, a)| &a.key).collect();
            let combined =
                CombinedUnidentifiedSenderAccessKeys::from_access_keys(keys);
            let request = MultiRecipientMessagesRequest {
                timestamp,
                online,
                urgent: true,
                story: false,
                payload: &payload,
                access: Some(MultiRecipientAccess::UnidentifiedAccessKey(
                    combined,
                )),
            };

            match self
                .unidentified_ws
                .send_multi_recipient_messages(request)
                .await
            {
                Ok(response) => {
                    let not_found: HashSet<ServiceId> =
                        response.uuids404.into_iter().collect();
                    let mut results = Vec::with_capacity(recipients.len());
                    for (recipient, _) in recipients {
                        if not_found.contains(recipient) {
                            results.push(Err(MessageSenderError::NotFound {
                                service_id: *recipient,
                            }));
                            continue;
                        }
                        let used_identity_key = self
                            .build_sent_message(*recipient, true, false)
                            .await?;
                        results.push(Ok(used_identity_key));
                    }
                    return Ok(results);
                },
                Err(e) => {
                    match self
                        .recover_from_multi_recipient_send_error(e)
                        .await?
                    {
                        SendRecovery::Retry => {},
                        SendRecovery::Terminal(err) => return Err(err),
                    }
                },
            }
        }

        Err(MessageSenderError::MaximumRetriesLimitExceeded)
    }

    /// Send a message (`content`) to an address (`recipient`).
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content, recipient),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    async fn try_send_message(
        &mut self,
        recipient: ServiceId,
        unidentified_access: Option<&UnidentifiedAccess>,
        mut content: crate::proto::Content,
        timestamp: u64,
        include_pni_signature: bool,
        online: bool,
    ) -> SendMessageResult {
        trace!("trying to send a message");

        use prost::Message;

        if include_pni_signature {
            content.pni_signature_message = Some(self.create_pni_signature()?);
        }

        let content_bytes = content.encode_to_vec();

        self.send_with_retries(
            recipient,
            unidentified_access,
            timestamp,
            online,
            true,
            async |sender, certificate| {
                let Some(EncryptedMessages { messages, .. }) = sender
                    .create_encrypted_messages(
                        &recipient,
                        certificate,
                        &content_bytes,
                    )
                    .await?
                else {
                    // this can happen for example when a device is primary, without any secondaries
                    // and we send a message to ourselves (which is only a SyncMessage { sent: ... })
                    // addressed to self
                    return Err(MessageSenderError::NoMessagesToSend);
                };
                Ok(messages)
            },
        )
        .await
    }

    /// Upload contact details to the CDN and send a sync message
    #[tracing::instrument(
        skip(self, unidentified_access, contacts, recipient),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub async fn send_contact_details<Contacts>(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<UnidentifiedAccess>,
        // XXX It may be interesting to use an intermediary type,
        //     instead of ContactDetails directly,
        //     because it allows us to add the avatar content.
        contacts: Contacts,
        online: bool,
        complete: bool,
    ) -> Result<(), MessageSenderError>
    where
        Contacts: IntoIterator<Item = ContactDetails>,
    {
        let ptr = self.upload_contact_details(contacts).await?;

        let msg = SyncMessage {
            content: Some(crate::proto::sync_message::Content::Contacts(
                sync_message::Contacts {
                    blob: Some(ptr),
                    complete: Some(complete),
                },
            )),
            ..SyncMessage::with_padding(&mut rng())
        };

        self.send_sync_message(msg).await?;

        Ok(())
    }

    /// Send `MessageRequestResponse` synchronization message with either a recipient ACI or a GroupV2 ID
    #[tracing::instrument(skip(self), fields(recipient = recipient.service_id_string()))]
    pub async fn send_message_request_response(
        &mut self,
        recipient: &ServiceId,
        thread: &ThreadIdentifier,
        action: message_request_response::Type,
    ) -> Result<(), MessageSenderError> {
        let message_request_response = match thread {
            ThreadIdentifier::Aci(aci) => {
                tracing::debug!(
                    "sending message request response {:?} for recipient {:?}",
                    action,
                    aci
                );
                MessageRequestResponse {
                    thread_aci: Some(aci.to_string()),
                    thread_aci_binary: Some(aci.into_bytes().to_vec()),
                    group_id: None,
                    r#type: Some(action.into()),
                }
            },
            ThreadIdentifier::Group(id) => {
                tracing::debug!(
                    "sending message request response {:?} for group {:?}",
                    action,
                    id
                );
                MessageRequestResponse {
                    thread_aci: None,
                    thread_aci_binary: None,
                    group_id: Some(id.to_vec()),
                    r#type: Some(action.into()),
                }
            },
        };

        let msg = SyncMessage {
            content: Some(
                crate::proto::sync_message::Content::MessageRequestResponse(
                    message_request_response,
                ),
            ),
            ..SyncMessage::with_padding(&mut rng())
        };

        let ts = Utc::now().timestamp_millis() as u64;
        self.send_message(recipient, None, msg, ts, false, false)
            .await?;

        Ok(())
    }

    /// Send a `SyncMessage` to own devices, if any.
    pub async fn send_sync_message(
        &mut self,
        sync: impl Into<SyncMessage>,
    ) -> Result<(), MessageSenderError> {
        if self.is_multi_device().await {
            let content: ContentBody = sync.into().into();
            let timestamp = Utc::now().timestamp_millis() as u64;
            debug!(
                "sending multi-device sync message with content {content:?}"
            );
            self.try_send_message(
                self.local_aci.into(),
                None,
                content.into_proto(),
                timestamp,
                false,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Send a `SyncMessage` request message
    #[tracing::instrument(skip(self))]
    pub async fn send_sync_message_request(
        &mut self,
        recipient: &ServiceId,
        request_type: sync_message::request::Type,
    ) -> Result<(), MessageSenderError> {
        if self.device_id == *DEFAULT_DEVICE_ID {
            return Err(MessageSenderError::SendSyncMessageError(request_type));
        }

        let msg = SyncMessage {
            content: Some(crate::proto::sync_message::Content::Request(
                sync_message::Request {
                    r#type: Some(request_type.into()),
                },
            )),
            ..SyncMessage::with_padding(&mut rng())
        };
        self.send_sync_message(msg).await?;

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn create_pni_signature(
        &mut self,
    ) -> Result<crate::proto::PniSignatureMessage, MessageSenderError> {
        let mut rng = rng();
        let signature = self
            .pni_identity
            .expect("PNI key set when PNI signature requested")
            .sign_alternate_identity(
                self.aci_identity.identity_key(),
                &mut rng,
            )?;
        Ok(crate::proto::PniSignatureMessage {
            pni: Some(self.local_pni.service_id_binary()),
            signature: Some(signature.into()),
        })
    }

    /// Enumerate all known devices for a recipient, always including the primary
    /// device, never including the local sender device.
    ///
    /// Mirrors Java's group-send device enumeration: the local device is excluded
    /// because we never need to send to ourselves.
    async fn enumerate_recipient_devices(
        &self,
        recipient: &ServiceId,
    ) -> Result<HashSet<DeviceId>, MessageSenderError> {
        let mut devices: HashSet<DeviceId> = self
            .protocol_store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .collect();

        // always send to the primary device no matter what
        devices.insert(*DEFAULT_DEVICE_ID);

        // never try to send messages to the sender device
        match recipient {
            ServiceId::Aci(aci) => {
                if *aci == self.local_aci {
                    devices.remove(&self.device_id);
                }
            },
            ServiceId::Pni(pni) => {
                if *pni == self.local_pni {
                    devices.remove(&self.device_id);
                }
            },
        };

        Ok(devices)
    }

    /// Load the sessions of every enumerated device of `recipient`, or
    /// `None` if any device lacks one.
    ///
    /// Used to decide multi-recipient eligibility: a recipient without a
    /// complete session set is routed to the 1:1 path, which establishes
    /// the missing sessions.
    async fn collect_recipient_sessions(
        &self,
        recipient: ServiceId,
    ) -> Result<Option<Vec<(ProtocolAddress, SessionRecord)>>, MessageSenderError>
    {
        let devices = self.enumerate_recipient_devices(&recipient).await?;
        let mut sessions = Vec::with_capacity(devices.len());
        for device_id in devices {
            let addr = recipient.to_protocol_address(device_id)?;
            let Some(session) = self.protocol_store.load_session(&addr).await?
            else {
                return Ok(None);
            };
            sessions.push((addr, session));
        }
        Ok(Some(sessions))
    }

    /// For every recipient device that does not yet have our SKDM for
    /// `distribution_id`, build it (idempotent: libsignal creates the chain on
    /// first call) and send it as a wire-only `proto::Content` with the SKDM
    /// attached. Mark each device shared on success.
    #[tracing::instrument(skip(self, recipients), fields(recipients = recipients.as_ref().len(), dist_id = %distribution_id))]
    async fn share_sender_key_if_needed(
        &mut self,
        distribution_id: Uuid,
        timestamp: u64,
        recipients: &[(ServiceId, Option<UnidentifiedAccess>, bool)],
    ) -> Result<(), MessageSenderError> {
        let sender_address =
            self.local_aci.to_protocol_address(self.device_id)?;

        // PNI signatures are an individual-send concern (matches Signal-Android's
        // IndividualSendJob); the SKDM is sender-key infrastructure, so we don't
        // attach one here even when the recipient needs one.
        for (recipient, unidentified_access, _include_pni_signature) in
            recipients
        {
            // `try_send_message` fans out to *every* device of the recipient
            // (and creates sessions for any the server knows about but we
            // don't). So we send at most ONE SKDM per recipient, not one per
            // device — otherwise a D-device recipient gets the SKDM D times.
            let devices = self.enumerate_recipient_devices(recipient).await?;
            let mut needs_share = false;
            for &device_id in &devices {
                let recipient_address =
                    match (*recipient).to_protocol_address(device_id) {
                        Ok(a) => a,
                        Err(_) => {
                            needs_share = true;
                            break;
                        },
                    };
                if !self
                    .protocol_store
                    .is_sender_key_shared(distribution_id, &recipient_address)
                    .await?
                {
                    needs_share = true;
                }
            }
            if !needs_share {
                continue;
            }

            let mut rng = rng();
            let skdm = create_sender_key_distribution_message(
                &sender_address,
                distribution_id,
                &mut self.protocol_store,
                &mut rng,
            )
            .await?;

            let content = crate::proto::Content {
                content: None,
                sender_key_distribution_message: Some(skdm.as_ref().to_vec()),
                pni_signature_message: None,
            };
            let _result = self
                .try_send_message(
                    *recipient,
                    unidentified_access.as_ref(),
                    content,
                    timestamp,
                    false,
                    false,
                )
                .await?;
            // `try_send_message` may have established sessions with
            // devices we didn't know about; re-enumerate so we mark
            // the *complete* device set shared.
            let devices_after =
                self.enumerate_recipient_devices(recipient).await?;
            for &device_id in &devices_after {
                let recipient_address =
                    (*recipient).to_protocol_address(device_id)?;
                self.protocol_store
                    .mark_sender_key_shared(distribution_id, &recipient_address)
                    .await?;
            }
        }

        // No SKDM sync transcript.

        Ok(())
    }

    // Equivalent with `getEncryptedMessages`
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    async fn create_encrypted_messages(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<&SenderCertificate>,
        content: &[u8],
    ) -> Result<Option<EncryptedMessages>, MessageSenderError> {
        let mut messages = vec![];

        let devices = self.enumerate_recipient_devices(recipient).await?;

        for device_id in devices {
            trace!("sending message to device {}", device_id);
            // `create_encrypted_message` may fail with `SessionNotFound` if the session is corrupted;
            // see https://github.com/whisperfish/libsignal-client/commit/601454d20.
            // If this happens, delete the session and retry.
            for _attempt in 0..2 {
                match self
                    .create_encrypted_message(
                        recipient,
                        unidentified_access,
                        device_id,
                        content,
                    )
                    .await
                {
                    Ok(message) => {
                        messages.push(message);
                        break;
                    },
                    Err(MessageSenderError::ServiceError(
                        ServiceError::SignalProtocolError(
                            SignalProtocolError::SessionNotFound(
                                SessionNotFound {
                                    address: Some(addr),
                                    op,
                                },
                            ),
                        ),
                    )) => {
                        // SessionNotFound is returned on certain session corruption.
                        // Since delete_session *creates* a session if it doesn't exist,
                        // the NotFound error is an indicator of session corruption.
                        // Try to delete this session, if it gets succesfully deleted, retry.  Otherwise, fail.
                        tracing::warn!("Potential session corruption for {}, deleting session", addr);
                        match self.protocol_store.delete_session(&addr).await {
                            Ok(()) => continue,
                            Err(error) => {
                                tracing::warn!(%error, %addr, "failed to delete session");
                                return Err(
                                    SignalProtocolError::SessionNotFound(
                                        SessionNotFound::new(addr, op),
                                    )
                                    .into(),
                                );
                            },
                        }
                    },
                    Err(e) => return Err(e),
                }
            }
        }

        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some(EncryptedMessages { messages }))
        }
    }

    /// Equivalent to `getEncryptedMessage`
    ///
    /// When no session with the recipient exists, we need to create one.
    #[tracing::instrument(
        level = "trace",
        skip(self, unidentified_access, content),
        fields(unidentified_access = unidentified_access.is_some(), recipient = recipient.service_id_string()),
    )]
    pub(crate) async fn create_encrypted_message(
        &mut self,
        recipient: &ServiceId,
        unidentified_access: Option<&SenderCertificate>,
        device_id: DeviceId,
        content: &[u8],
    ) -> Result<OutgoingPushMessage, MessageSenderError> {
        let recipient_protocol_address =
            recipient.to_protocol_address(device_id);

        tracing::trace!(
            "encrypting message for {}",
            recipient_protocol_address
        );

        // establish a session with the recipient/device if necessary
        // no need to establish a session with ourselves (and our own current device)
        if self
            .protocol_store
            .load_session(&recipient_protocol_address)
            .await?
            .is_none()
        {
            info!(
                "establishing new session with {}",
                recipient_protocol_address
            );
            let pre_keys = match self
                .identified_ws
                .get_pre_keys(recipient, device_id)
                .await
            {
                Ok(ok) => {
                    tracing::trace!("Get prekeys OK");
                    ok
                },
                Err(ServiceError::NotFoundError) => {
                    return Err(MessageSenderError::NotFound {
                        service_id: *recipient,
                    });
                },
                Err(e) => Err(e)?,
            };

            let mut rng = rng();

            for pre_key_bundle in pre_keys {
                if recipient == &self.local_aci
                    && self.device_id == pre_key_bundle.device_id()?
                {
                    trace!("not establishing a session with myself!");
                    continue;
                }

                let pre_key_address = get_preferred_protocol_address(
                    &self.protocol_store,
                    recipient,
                    pre_key_bundle.device_id()?,
                )
                .await?;

                process_prekey_bundle(
                    &pre_key_address,
                    &self
                        .local_aci
                        .to_protocol_address(self.device_id)
                        .expect("valid device id"),
                    &mut self.protocol_store.clone(),
                    &mut self.protocol_store,
                    &pre_key_bundle,
                    SystemTime::now(),
                    &mut rng,
                )
                .await?;
            }
        }

        let message = self
            .cipher
            .encrypt(
                &recipient_protocol_address,
                unidentified_access,
                content,
                &mut rng(),
            )
            .instrument(tracing::trace_span!("encrypting message"))
            .await?;

        Ok(message)
    }

    fn create_multi_device_sent_transcript_content<'a>(
        &mut self,
        recipient: Option<&ServiceId>,
        content_body: ContentBody,
        timestamp: u64,
        send_message_results: impl IntoIterator<Item = &'a SendMessageResult>,
    ) -> Option<ContentBody> {
        use sync_message::sent::UnidentifiedDeliveryStatus;
        let (message, edit_message) = match content_body {
            ContentBody::DataMessage(m) => (Some(m), None),
            ContentBody::EditMessage(m) => (None, Some(m)),
            content_body => {
                tracing::trace!(?content_body, "not syncing to self");
                return None;
            },
        };
        let unidentified_status: Vec<UnidentifiedDeliveryStatus> =
            send_message_results
                .into_iter()
                .filter_map(|result| result.as_ref().ok())
                .map(|sent| {
                    let SentMessage {
                        recipient,
                        unidentified,
                        used_identity_key,
                        ..
                    } = sent;
                    UnidentifiedDeliveryStatus {
                        destination_service_id: Some(
                            recipient.service_id_string(),
                        ),
                        destination_service_id_binary: Some(
                            recipient.service_id_binary(),
                        ),
                        unidentified: Some(*unidentified),
                        destination_pni_identity_key: Some(
                            used_identity_key.serialize().into(),
                        ),
                    }
                })
                .collect();
        Some(ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(sync_message::Content::Sent(sync_message::Sent {
                destination_service_id: recipient
                    .map(ServiceId::service_id_string),
                destination_service_id_binary: recipient
                    .map(ServiceId::service_id_binary),
                destination_e164: None,
                expiration_start_timestamp: message
                    .as_ref()
                    .and_then(|m| m.expire_timer)
                    .map(|_| timestamp),
                message,
                edit_message,
                timestamp: Some(timestamp),
                unidentified_status,
                ..Default::default()
            })),
            ..SyncMessage::with_padding(&mut rng())
        }))
    }

    /// Handle an inbound `DecryptionErrorMessage` for sender-key recovery.
    ///
    /// When `ratchet_key` is `None`, the failure was a `SenderKeyMessage`
    /// decryption (a `DecryptionErrorMessage` built from a `SenderKeyMessage`
    /// carries no ratchet key). In that case we clear all shared sender-key
    /// state for `sender`, so the next group send re-distributes the SKDM
    /// and re-sends the payload to them.
    ///
    /// When `ratchet_key` is `Some`, the failure was a 1:1 `Whisper`/`PreKey`
    /// message; that's session-recovery territory, not sender keys, and this
    /// method is a no-op for it.
    ///
    /// This does NOT reset the 1:1 session.
    ///
    /// `error` is the *proto* `DecryptionErrorMessage` (as received on the wire
    /// and surfaced via `ContentBody::DecryptionErrorMessage`); we re-derive
    /// the `libsignal_protocol` type to inspect `ratchet_key`.
    #[tracing::instrument(skip(self))]
    pub async fn handle_decryption_error_message(
        &mut self,
        error: &crate::proto::DecryptionErrorMessage,
        sender: &ProtocolAddress,
    ) -> Result<(), MessageSenderError> {
        use prost::Message as _;
        let bytes = error.encode_to_vec();
        let crypto_error =
            libsignal_protocol::DecryptionErrorMessage::try_from(&bytes[..])
                .map_err(MessageSenderError::ProtocolError)?;
        if crypto_error.ratchet_key().is_some() {
            tracing::trace!(
                ?sender,
                "DecryptionErrorMessage has a ratchet key; 1:1 session recovery, not sender keys"
            );
            return Ok(());
        }
        tracing::info!(
            ?sender,
            "SenderKey DecryptionErrorMessage from; clearing shared state so next send re-shares"
        );
        self.protocol_store
            .clear_sender_key_shared_for_address(sender)
            .await?;
        Ok(())
    }
}
