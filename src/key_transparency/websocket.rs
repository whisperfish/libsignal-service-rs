//! WebSocket transport for Key Transparency operations.
//!
//! Provides structured JSON request/response types for the Signal KT server API,
//! exchanged over the Signal chat WebSocket connection.
//!
//! The three endpoints mirror the server API:
//!
//! * `POST /v1/key-transparency/search`
//! * `GET  /v1/key-transparency/distinguished?lastTreeHeadSize={}`
//! * `POST /v1/key-transparency/monitor`

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use libsignal_core::{Aci, E164};
use libsignal_keytrans::{
    ChatDistinguishedResponse, ChatMonitorResponse, ChatSearchResponse,
    MonitorRequest, MonitorResponse,
};
use prost::Message;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::push_service::ServiceError;
use crate::utils::{
    serde_base64, serde_optional_base64, serde_optional_base64url, TryIntoE164,
};
use crate::websocket::{SignalWebSocket, Unidentified};

use super::KeyTransparencyStore;

#[derive(Error, Debug)]
pub enum KeyTransparencyWebSocketError {
    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
    #[error("WebSocket transport error: {0}")]
    WebSocket(#[from] ServiceError),
    #[error("request formatting error: {0}")]
    RequestError(&'static str),
}

/// Owned monitor request value, deserialized from storage.
///
/// This mirrors the protobuf `MonitorRequest` but owns its data,
/// so it can be passed across async boundaries without lifetime issues.
#[derive(Debug)]
pub struct ValueMonitor {
    pub aci: Aci,
    pub e164: Option<String>,
    pub username_hash: Option<Vec<u8>>,
    pub commitment_index: Vec<u8>,
}

/// JSON request body for `POST /v1/key-transparency/search`.
///
/// Corresponds to the request body expected by Signal-Server:
/// `service/src/main/java/org/wfromhispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatSearchRequest {
    pub aci: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e164: Option<String>,
    /// Base64-encoded username hash, matching Signal-Server's expectations.
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_base64url"
    )]
    pub username_hash: Option<Vec<u8>>,
    #[serde(with = "serde_base64")]
    pub aci_identity_key: Vec<u8>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_base64"
    )]
    pub unidentified_access_key: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_tree_head_size: Option<u64>,
    pub distinguished_tree_head_size: u64,
}

impl<P> TryFrom<super::ChatSearchParams<P>> for RawChatSearchRequest
where
    P: TryIntoE164,
{
    type Error = KeyTransparencyWebSocketError;

    fn try_from(
        params: super::ChatSearchParams<P>,
    ) -> Result<Self, Self::Error> {
        // `unidentifiedAccessKey` is the e164's UAK (derived from the target's
        // profile key) and is only sent alongside an e164; see libsignal-net
        // `RawChatSearchRequest::new` and Signal-Android.
        let e164 = params
            .target_e164
            .map(|e| e.try_into_e164())
            .transpose()
            .map_err(|_e| {
                KeyTransparencyWebSocketError::RequestError(
                    "unparsable phone number",
                )
            })?;
        let unidentified_access_key = e164
            .as_ref()
            .and(params.target_profile_key.as_ref())
            .map(|pk| pk.derive_access_key().to_vec());
        Ok(RawChatSearchRequest {
            aci: params.target_aci.service_id_string(),
            e164: e164.as_ref().map(E164::to_string),
            username_hash: params
                .target_username
                .as_ref()
                .map(|u| u.hash().to_vec()),
            aci_identity_key: params.target_identity_key.serialize().to_vec(),
            unidentified_access_key,
            last_tree_head_size: params.last_tree_head_size,
            distinguished_tree_head_size: params
                .distinguished_tree_head_size
                .unwrap_or(0),
        })
    }
}

/// JSON response body for `POST /v1/key-transparency/search`.
///
/// The `serialized_response` field is a base64-encoded protobuf
/// `ChatSearchResponse` containing the search result and tree head data.
///
/// Corresponds to the response from Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawChatSearchResponse {
    #[serde(with = "serde_base64")]
    pub serialized_response: Vec<u8>,
}

/// JSON response body for `GET /v1/key-transparency/distinguished`.
///
/// The `serialized_response` field is a base64-encoded protobuf
/// `ChatDistinguishedResponse` containing the distinguished tree head.
///
/// Corresponds to the response from Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawChatDistinguishedResponse {
    #[serde(with = "serde_base64")]
    pub serialized_response: Vec<u8>,
}

/// JSON sub-structure for a single monitored value in a monitor request.
///
/// Corresponds to the value entry in Signal-Server's monitor endpoint:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatValueMonitorRequest {
    pub value: String,
    pub entry_position: u64,
    #[serde(with = "crate::utils::serde_base64_no_pad")]
    pub commitment_index: Vec<u8>,
}

/// JSON request body for `POST /v1/key-transparency/monitor`.
///
/// Corresponds to the request body expected by Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawChatMonitorRequest {
    pub aci: RawChatValueMonitorRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e164: Option<RawChatValueMonitorRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_hash: Option<RawChatValueMonitorRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_non_distinguished_tree_head_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_distinguished_tree_head_size: Option<u64>,
}

/// JSON response body for `POST /v1/key-transparency/monitor`.
///
/// The `serialized_response` field is a base64-encoded protobuf
/// `ChatMonitorResponse` containing the monitor result and tree head data.
///
/// Corresponds to the response from Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawChatMonitorResponse {
    #[serde(with = "serde_base64")]
    pub serialized_response: Vec<u8>,
}

/// Raw tree head data extracted from a Key Transparency response.
///
/// Tree heads are returned inside the protobuf `serialized_response`
/// of search, distinguished, and monitor responses.  This type represents
/// the JSON-equivalent fields that would appear if the server exposed
/// the tree head directly.
///
/// Corresponds to the tree head data in Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawChatTreeHead {
    pub tree_head_size: u64,
    pub epoch_id: u64,
    #[serde(with = "serde_base64")]
    pub root_hash: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

/// Events that can be received over the Signal chat WebSocket for Key Transparency.
///
/// Each variant wraps the corresponding raw JSON response type received from the
/// Signal-Server endpoint.
///
/// Corresponds to the response types in Signal-Server:
/// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
///
/// See also libsignal-net:
/// - `rust/net/chat/src/api/keytrans.rs`
/// - `rust/net/chat/src/ws/keytrans.rs`
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum WebSocketChatEvent {
    Search(RawChatSearchResponse),
    Distinguished(RawChatDistinguishedResponse),
    Monitor(RawChatMonitorResponse),
}

// ---------------------------------------------------------------------------
// SignalWebSocket helper methods

impl SignalWebSocket<Unidentified> {
    /// Sends a KT search request.
    ///
    /// Corresponds to `POST /v1/key-transparency/search` in Signal-Server:
    /// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
    ///
    /// See also libsignal-net:
    /// - `rust/net/chat/src/api/keytrans.rs`
    /// - `rust/net/chat/src/ws/keytrans.rs`
    pub async fn key_transparency_search<P>(
        &mut self,
        params: super::ChatSearchParams<P>,
    ) -> Result<ChatSearchResponse, KeyTransparencyWebSocketError>
    where
        P: TryIntoE164,
    {
        let request: RawChatSearchRequest = params.try_into()?;

        let raw: RawChatSearchResponse = self
            .http_request(Method::POST, "/v1/key-transparency/search")?
            .send_json(Some(request))
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        let response = ChatSearchResponse::decode(&*raw.serialized_response)?;
        Ok(response)
    }

    /// Fetches the distinguished KT tree head.
    ///
    /// Corresponds to `GET /v1/key-transparency/distinguished?lastTreeHeadSize={}` in Signal-Server:
    /// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
    ///
    /// See also libsignal-net:
    /// - `rust/net/chat/src/api/keytrans.rs`
    /// - `rust/net/chat/src/ws/keytrans.rs`
    pub async fn key_transparency_distinguished(
        &mut self,
        last_tree_head_size: Option<u64>,
    ) -> Result<ChatDistinguishedResponse, ServiceError> {
        let mut path = String::from("/v1/key-transparency/distinguished");
        if let Some(size) = last_tree_head_size {
            path.push_str(&format!("?lastTreeHeadSize={}", size));
        }

        let raw: RawChatDistinguishedResponse = self
            .http_request(Method::GET, &path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        let response =
            ChatDistinguishedResponse::decode(&*raw.serialized_response)
                .map_err(|e| ServiceError::SendError {
                    reason: format!("protobuf decode: {}", e),
                })?;
        Ok(response)
    }

    /// Sends a KT monitor request.
    ///
    /// Corresponds to `POST /v1/key-transparency/monitor` in Signal-Server:
    /// `service/src/main/java/org/whispersystems/textsecuregcm/controllers/KeyTransparencyController.java`
    ///
    /// See also libsignal-net:
    /// - `rust/net/chat/src/api/keytrans.rs`
    /// - `rust/net/chat/src/ws/keytrans.rs`
    pub async fn key_transparency_monitor(
        &mut self,
        request: &MonitorRequest,
        last_non_distinguished_tree_head_size: Option<u64>,
        last_distinguished_tree_head_size: Option<u64>,
    ) -> Result<MonitorResponse, KeyTransparencyWebSocketError> {
        let mut aci = None;
        let mut e164 = None;
        let mut username_hash = None;

        for key in &request.keys {
            let prefix = key.search_key.first().ok_or_else(|| {
                KeyTransparencyWebSocketError::RequestError(
                    "empty search key in MonitorRequest",
                )
            })?;
            let value_bytes = &key.search_key[1..];

            match prefix {
                b'a' => {
                    let parsed = Aci::parse_from_service_id_binary(value_bytes)
                        .ok_or_else(|| {
                            KeyTransparencyWebSocketError::RequestError(
                                "invalid ACI search key in MonitorRequest",
                            )
                        })?;
                    aci = Some(RawChatValueMonitorRequest {
                        value: parsed.service_id_string(),
                        entry_position: key.entry_position,
                        commitment_index: key.commitment_index.clone(),
                    });
                },
                b'n' => {
                    let e164_str = String::from_utf8(value_bytes.to_vec())
                        .map_err(|_| {
                            KeyTransparencyWebSocketError::RequestError(
                                "invalid E164 search key in MonitorRequest",
                            )
                        })?;
                    let parsed = e164_str.parse::<E164>().map_err(|_| {
                        KeyTransparencyWebSocketError::RequestError(
                            "invalid E164 search key in MonitorRequest",
                        )
                    })?;
                    e164 = Some(RawChatValueMonitorRequest {
                        value: parsed.to_string(),
                        entry_position: key.entry_position,
                        commitment_index: key.commitment_index.clone(),
                    });
                },
                b'u' => {
                    username_hash = Some(RawChatValueMonitorRequest {
                        value: URL_SAFE_NO_PAD.encode(value_bytes),
                        entry_position: key.entry_position,
                        commitment_index: key.commitment_index.clone(),
                    });
                },
                _ => {
                    panic!(
                        "unknown prefix byte {:#x} in MonitorRequest",
                        prefix
                    )
                },
            }
        }

        let aci = aci.ok_or_else(|| {
            KeyTransparencyWebSocketError::RequestError(
                "missing ACI key in MonitorRequest",
            )
        })?;

        let has_e164 = e164.is_some();
        let has_username_hash = username_hash.is_some();

        let body = RawChatMonitorRequest {
            aci,
            e164,
            username_hash,
            last_non_distinguished_tree_head_size,
            last_distinguished_tree_head_size,
        };

        let raw: RawChatMonitorResponse = self
            .http_request(Method::POST, "/v1/key-transparency/monitor")?
            .send_json(Some(body))
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        // The chat server sends a `ChatMonitorResponse` (per-identifier
        // proofs); `verify_monitor` expects a `MonitorResponse` with proofs
        // in request order. Map aci, then e164, then username_hash.
        let chat = ChatMonitorResponse::decode(&*raw.serialized_response)?;
        let mut proofs = Vec::with_capacity(
            1 + has_e164 as usize + has_username_hash as usize,
        );
        let aci_proof = chat.aci.ok_or_else(|| {
            KeyTransparencyWebSocketError::RequestError(
                "missing ACI monitor proof",
            )
        })?;
        proofs.push(aci_proof);
        if let Some(p) = chat.e164 {
            proofs.push(p);
        }
        if let Some(p) = chat.username_hash {
            proofs.push(p);
        }
        let response = MonitorResponse {
            tree_head: chat.tree_head,
            proofs,
            inclusion: chat.inclusion,
        };
        Ok(response)
    }

    /// Creates a KeyTransparencyClient for this websocket connection.
    ///
    /// This is a convenience method that constructs a KeyTransparencyClient
    /// with the given config and store, using this websocket for transport.
    pub fn key_transparency<'a, S: KeyTransparencyStore>(
        &'a mut self,
        config: super::PublicConfig,
        store: &'a S,
    ) -> super::KeyTransparencyClient<'a, S> {
        super::KeyTransparencyClient::new(config, store, self)
    }
}

/// Parses a [`ValueMonitor`] into a protobuf [`MonitorRequest`].
///
/// The protobuf expects a list of [`MonitorKey`] entries, one per monitored value.
/// Each entry carries the opaque search key, the entry position, and the commitment index.
pub fn value_monitor_to_request(
    value: &ValueMonitor,
) -> Result<MonitorRequest, ServiceError> {
    let mut request = MonitorRequest::default();

    let aci_search_key = [
        b"a",
        libsignal_core::ServiceId::from(value.aci)
            .service_id_binary()
            .as_slice(),
    ]
    .concat();

    request.keys.push(libsignal_keytrans::MonitorKey {
        search_key: aci_search_key,
        entry_position: 0, // TODO: filled from AccountData
        commitment_index: value.commitment_index.clone(),
    });

    if let Some(ref e164) = value.e164 {
        let e164_search_key = [b"n", e164.as_bytes()].concat();
        request.keys.push(libsignal_keytrans::MonitorKey {
            search_key: e164_search_key,
            entry_position: 0, // TODO
            commitment_index: value.commitment_index.clone(),
        });
    }

    if let Some(ref username_hash) = value.username_hash {
        let u_search_key = [b"u", username_hash.as_slice()].concat();
        request.keys.push(libsignal_keytrans::MonitorKey {
            search_key: u_search_key,
            entry_position: 0, // TODO
            commitment_index: value.commitment_index.clone(),
        });
    }

    Ok(request)
}
