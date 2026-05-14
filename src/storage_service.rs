//! Signal Storage Service client.
//!
//! Storage Service is Signal's encrypted, server-stored, multi-device-shared
//! account state (contacts, group memberships, account settings, …). It
//! superseded the legacy `SyncMessage::Contacts` mechanism around 2019:
//! modern primaries answer a legacy contact-sync request with an empty stub
//! and expect linked devices to pull state from here instead.
//!
//! ## Crypto
//!
//! Every blob (the manifest and each item) is AES-256-GCM with a 12-byte IV
//! prepended — wire format `iv (12B) || ciphertext+tag`.
//!
//! - manifest key      = `HMAC-SHA256(storage_key, "Manifest_{version}")`
//! - item key (modern) = `HKDF-SHA256(ikm = recordIkm, info = "20240801_SIGNAL_STORAGE_SERVICE_ITEM_" || raw_id)`
//! - item key (legacy) = `HMAC-SHA256(storage_key, "Item_" + base64(raw_id))`
//!
//! `storage_key` is the account-derived [`StorageServiceKey`].
//!
//! Reference (Signal-Android, tag v8.3.1):
//! - `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/storage/StorageServiceApi.kt`
//! - `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/storage/SignalStorageCipher.kt`
//! - `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/storage/RecordIkm.kt`
//! - `core/models-jvm/src/main/java/org/signal/core/models/storageservice/StorageKey.kt`

use aes::cipher::Unsigned;
use aes_gcm::aead::{Aead, AeadCore, AeadInPlace};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use rand::TryRngCore;
use reqwest::Method;
use serde::Deserialize;
use sha2::Sha256;

use crate::configuration::Endpoint;
use crate::master_key::StorageServiceKey;
use crate::proto::{
    ManifestRecord, ReadOperation, StorageItem, StorageItems, StorageManifest,
    StorageRecord,
};
use crate::push_service::protobuf::ProtobufResponseExt;
use crate::push_service::ReqwestExt;
use crate::push_service::{
    HttpAuth, HttpAuthOverride, PushService, ServiceError,
};

const IV_LEN: usize = 12;
const ITEM_KEY_INFO_PREFIX: &[u8] = b"20240801_SIGNAL_STORAGE_SERVICE_ITEM_";

type HmacSha256 = Hmac<Sha256>;

/// Errors from the Storage Service.
#[derive(Debug, thiserror::Error)]
pub enum StorageServiceError {
    /// The blob couldn't be decrypted or didn't decode — wrong key, tampered,
    /// truncated, or not the protobuf we expected. Not distinguished further
    /// because there's nothing the caller can do differently.
    #[error("invalid storage service blob")]
    Invalid,
    #[error("network / service error: {0}")]
    Service(#[from] ServiceError),
}

impl From<prost::DecodeError> for StorageServiceError {
    fn from(_: prost::DecodeError) -> Self {
        StorageServiceError::Invalid
    }
}

impl From<reqwest::Error> for StorageServiceError {
    fn from(e: reqwest::Error) -> Self {
        StorageServiceError::Service(e.into())
    }
}

/// Body of `GET /v1/storage/auth`.
#[derive(Debug, Deserialize)]
struct StorageAuthResponse {
    username: String,
    password: String,
}

/// Authenticated Storage Service handle.
///
/// Wraps a [`PushService`] plus the short-lived basic-auth credentials and
/// the account [`StorageServiceKey`], so callers get decrypted protobufs
/// straight out and never touch the wire crypto themselves.
pub struct StorageService {
    service: PushService,
    credentials: HttpAuth,
    storage_key: StorageServiceKey,
}

impl StorageService {
    /// Authenticate against the storage service.
    ///
    /// Fetches a fresh basic-auth token (`GET /v1/storage/auth`); the token
    /// is good for ~24h server-side but cheap enough to re-fetch per sync.
    pub async fn new(
        service: PushService,
        storage_key: StorageServiceKey,
    ) -> Result<Self, ServiceError> {
        let resp: StorageAuthResponse = service
            .request(
                Method::GET,
                Endpoint::service("/v1/storage/auth"),
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        let credentials = HttpAuth {
            username: resp.username,
            password: resp.password,
        };
        Ok(Self {
            service,
            credentials,
            storage_key,
        })
    }

    /// Fetch and decrypt the latest manifest.
    pub async fn manifest(
        &self,
    ) -> Result<ManifestRecord, StorageServiceError> {
        let manifest: StorageManifest = self
            .service
            .request(
                Method::GET,
                Endpoint::storage("/v1/storage/manifest"),
                HttpAuthOverride::Identified(self.credentials.clone()),
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .protobuf()
            .await?;
        Self::decrypt_manifest(&self.storage_key, &manifest)
    }

    /// Fetch and decrypt the manifest only if the server's version differs
    /// from `version`. `Ok(None)` means the server matched (HTTP 204).
    pub async fn manifest_if_changed(
        &self,
        version: u64,
    ) -> Result<Option<ManifestRecord>, StorageServiceError> {
        let response = self
            .service
            .request(
                Method::GET,
                Endpoint::storage(format!(
                    "/v1/storage/manifest/version/{version}"
                )),
                HttpAuthOverride::Identified(self.credentials.clone()),
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        if response.status().as_u16() == 204 {
            return Ok(None);
        }
        let manifest: StorageManifest = response.protobuf().await?;
        Ok(Some(Self::decrypt_manifest(&self.storage_key, &manifest)?))
    }

    /// Fetch and decrypt storage items by key.
    ///
    /// `keys` are `Identifier.raw` blobs from [`ManifestRecord::identifiers`];
    /// `record_ikm` is [`ManifestRecord::record_ikm`] (empty on legacy
    /// accounts, in which case the per-item key is derived from the storage
    /// key directly). Items the server doesn't return are simply absent from
    /// the result.
    pub async fn read_items(
        &self,
        keys: Vec<Vec<u8>>,
        record_ikm: Option<&[u8]>,
    ) -> Result<Vec<StorageRecord>, StorageServiceError> {
        let body = ReadOperation { read_key: keys };
        let mut buf = Vec::with_capacity(body.encoded_len());
        body.encode(&mut buf).expect("infallible encode into Vec");

        let items: StorageItems = self
            .service
            .request(
                Method::PUT,
                Endpoint::storage("/v1/storage/read"),
                HttpAuthOverride::Identified(self.credentials.clone()),
            )?
            .header("Content-Type", "application/x-protobuf")
            .body(buf)
            .send()
            .await?
            .service_error_for_status()
            .await?
            .protobuf()
            .await?;

        items
            .items
            .iter()
            .map(|item| Self::decrypt_item(&self.storage_key, item, record_ikm))
            .collect()
    }

    // -- crypto ------------------------------------------------------------

    /// Decrypt a [`StorageManifest`] into a [`ManifestRecord`].
    pub fn decrypt_manifest(
        storage_key: &StorageServiceKey,
        manifest: &StorageManifest,
    ) -> Result<ManifestRecord, StorageServiceError> {
        let key = Self::manifest_key(storage_key, manifest.version);
        let plaintext = decrypt(&key, &manifest.value)?;
        Ok(ManifestRecord::decode(&*plaintext)?)
    }

    /// Encrypt a [`ManifestRecord`] into a [`StorageManifest`] ready to PUT.
    pub fn encrypt_manifest(
        storage_key: &StorageServiceKey,
        record: &ManifestRecord,
    ) -> StorageManifest {
        let key = Self::manifest_key(storage_key, record.version);
        StorageManifest {
            version: record.version,
            value: encrypt(&key, &record.encode_to_vec()),
        }
    }

    /// Decrypt a [`StorageItem`] into a [`StorageRecord`].
    pub fn decrypt_item(
        storage_key: &StorageServiceKey,
        item: &StorageItem,
        record_ikm: Option<&[u8]>,
    ) -> Result<StorageRecord, StorageServiceError> {
        let key = Self::item_key(storage_key, &item.key, record_ikm);
        let plaintext = decrypt(&key, &item.value)?;
        Ok(StorageRecord::decode(&*plaintext)?)
    }

    /// Encrypt a [`StorageRecord`] into a [`StorageItem`] ready to PUT.
    ///
    /// `raw_id` is the item's identifier; `record_ikm` should match what's
    /// in the manifest this item will be referenced from.
    pub fn encrypt_item(
        storage_key: &StorageServiceKey,
        raw_id: Vec<u8>,
        record: &StorageRecord,
        record_ikm: Option<&[u8]>,
    ) -> StorageItem {
        let key = Self::item_key(storage_key, &raw_id, record_ikm);
        StorageItem {
            key: raw_id,
            value: encrypt(&key, &record.encode_to_vec()),
        }
    }

    /// `HMAC-SHA256(storage_key, "Manifest_{version}")`.
    fn manifest_key(storage_key: &StorageServiceKey, version: u64) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&storage_key.inner)
            .expect("HMAC accepts any key length");
        mac.update(b"Manifest_");
        mac.update(version.to_string().as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Per-item key. Modern accounts carry a `record_ikm` in the manifest and
    /// derive via HKDF; legacy accounts derive straight off the storage key.
    fn item_key(
        storage_key: &StorageServiceKey,
        raw_id: &[u8],
        record_ikm: Option<&[u8]>,
    ) -> [u8; 32] {
        match record_ikm {
            Some(ikm) if !ikm.is_empty() => {
                let hk = Hkdf::<Sha256>::new(None, ikm);
                let mut okm = [0u8; 32];
                hk.expand_multi_info(&[ITEM_KEY_INFO_PREFIX, raw_id], &mut okm)
                    .expect("32-byte HKDF output is valid");
                okm
            },
            _ => {
                let b64 =
                    base64::engine::general_purpose::STANDARD.encode(raw_id);
                let mut mac =
                    <HmacSha256 as Mac>::new_from_slice(&storage_key.inner)
                        .expect("HMAC accepts any key length");
                mac.update(b"Item_");
                mac.update(b64.as_bytes());
                mac.finalize().into_bytes().into()
            },
        }
    }
}

/// AES-256-GCM decrypt of `iv(12) || ciphertext+tag`.
fn decrypt(
    key: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>, StorageServiceError> {
    if blob.len() < IV_LEN {
        return Err(StorageServiceError::Invalid);
    }
    let (iv, ct) = blob.split_at(IV_LEN);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(iv), ct)
        .map_err(|_| StorageServiceError::Invalid)
}

/// AES-256-GCM encrypt, producing `iv(12) || ciphertext+tag` with a fresh
/// random IV.
fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; IV_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut iv)
        .expect("OS RNG available");

    // Single allocation: IV + plaintext + tag
    let mut out = Vec::with_capacity(
        IV_LEN + plaintext.len() + <Aes256Gcm as AeadCore>::TagSize::to_usize(),
    );
    out.extend_from_slice(&iv);
    out.extend_from_slice(plaintext);

    // Encrypt in place - returns tag separately
    let tag = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt_in_place_detached(
            Nonce::from_slice(&iv),
            b"",
            &mut out[IV_LEN..],
        )
        .expect("AES-256-GCM encryption is infallible for valid keys");

    // Append the tag
    out.extend_from_slice(&tag);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trip() {
        let storage_key = StorageServiceKey { inner: [7u8; 32] };
        let record = ManifestRecord {
            version: 42,
            source_device: 1,
            identifiers: vec![],
            record_ikm: vec![],
        };
        let encrypted = StorageService::encrypt_manifest(&storage_key, &record);
        assert_eq!(encrypted.version, 42);
        let decrypted =
            StorageService::decrypt_manifest(&storage_key, &encrypted).unwrap();
        assert_eq!(decrypted, record);
    }

    #[test]
    fn item_round_trip_modern_and_legacy() {
        let storage_key = StorageServiceKey { inner: [9u8; 32] };
        let raw_id = vec![0xABu8; 16];
        let record = StorageRecord { record: None };

        // Legacy path (no record_ikm).
        let legacy = StorageService::encrypt_item(
            &storage_key,
            raw_id.clone(),
            &record,
            None,
        );
        assert_eq!(
            StorageService::decrypt_item(&storage_key, &legacy, None).unwrap(),
            record
        );

        // Modern path (HKDF off a record_ikm).
        let ikm = [4u8; 32];
        let modern = StorageService::encrypt_item(
            &storage_key,
            raw_id.clone(),
            &record,
            Some(&ikm),
        );
        assert_eq!(
            StorageService::decrypt_item(&storage_key, &modern, Some(&ikm))
                .unwrap(),
            record
        );
    }

    #[test]
    fn modern_and_legacy_keys_differ() {
        let storage_key = StorageServiceKey { inner: [3u8; 32] };
        let raw_id = [5u8; 16];
        let legacy = StorageService::item_key(&storage_key, &raw_id, None);
        let modern =
            StorageService::item_key(&storage_key, &raw_id, Some(&[4u8; 32]));
        assert_ne!(legacy, modern);
    }

    #[test]
    fn manifest_key_changes_with_version() {
        let storage_key = StorageServiceKey { inner: [1u8; 32] };
        assert_ne!(
            StorageService::manifest_key(&storage_key, 1),
            StorageService::manifest_key(&storage_key, 2)
        );
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let a = StorageServiceKey { inner: [1u8; 32] };
        let b = StorageServiceKey { inner: [2u8; 32] };
        let record = ManifestRecord {
            version: 1,
            source_device: 0,
            identifiers: vec![],
            record_ikm: vec![],
        };
        let encrypted = StorageService::encrypt_manifest(&a, &record);
        assert!(matches!(
            StorageService::decrypt_manifest(&b, &encrypted),
            Err(StorageServiceError::Invalid)
        ));
    }
}
