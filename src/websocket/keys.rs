use std::collections::HashMap;

use libsignal_core::DeviceId;
use libsignal_protocol::{
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey, SenderCertificate, ServiceId,
    ServiceIdKind, SignalProtocolError,
};
use reqwest::Method;
use serde::Deserialize;

use crate::{
    pre_keys::{
        KyberPreKeyEntity, PreKeyEntity, PreKeyState, SignedPreKeyEntity,
    },
    push_service::DEFAULT_DEVICE_ID,
    sender::OutgoingPushMessage,
    utils::{serde_base64, serde_device_id},
    websocket::{self, registration::VerifyAccountResponse, SignalWebSocket},
};

use super::ServiceError;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
    pub pq_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponse {
    #[serde(with = "serde_base64")]
    pub identity_key: Vec<u8>,
    pub devices: Vec<PreKeyResponseItem>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyResponseItem {
    #[serde(with = "serde_device_id")]
    pub device_id: DeviceId,
    pub registration_id: u32,
    pub signed_pre_key: SignedPreKeyEntity,
    pub pre_key: Option<PreKeyEntity>,
    pub pq_pre_key: KyberPreKeyEntity,
}

impl PreKeyResponseItem {
    pub(crate) fn into_bundle(
        self,
        identity: IdentityKey,
    ) -> Result<PreKeyBundle, ServiceError> {
        let pre_key_bundle = PreKeyBundle::new(
            self.registration_id,
            self.device_id,
            self.pre_key
                .map(|pk| -> Result<_, SignalProtocolError> {
                    Ok((
                        pk.key_id.into(),
                        PublicKey::deserialize(&pk.public_key)?,
                    ))
                })
                .transpose()?,
            // pre_key: Option<(u32, PublicKey)>,
            self.signed_pre_key.key_id.into(),
            PublicKey::deserialize(&self.signed_pre_key.public_key)?,
            self.signed_pre_key.signature,
            self.pq_pre_key.key_id.into(),
            Key::<Public>::deserialize(&self.pq_pre_key.public_key)?,
            self.pq_pre_key.signature,
            identity,
        )?;

        Ok(pre_key_bundle)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SenderCertificateJson {
    #[serde(with = "serde_base64")]
    certificate: Vec<u8>,
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn get_pre_key_status(
        &mut self,
        service_id_kind: ServiceIdKind,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.http_request(
            Method::GET,
            format!("/v2/keys?identity={}", service_id_kind),
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }

    /// Checks for consistency of the repeated-use keys
    ///
    /// Supply the digest as follows:
    /// `SHA256(identityKeyBytes || signedEcPreKeyId || signedEcPreKeyIdBytes || lastResortKeyId ||
    /// lastResortKeyBytes)`
    ///
    /// The IDs are represented as 8-byte big endian ints.
    ///
    /// Retuns `Ok(true)` if the view is consistent, `Ok(false)` if the view is inconsistent.
    pub async fn check_pre_keys(
        &mut self,
        service_id_kind: ServiceIdKind,
        digest: &[u8; 32],
    ) -> Result<bool, ServiceError> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct CheckPreKeysRequest<'a> {
            identity_type: String,
            #[serde(with = "serde_base64")]
            digest: &'a [u8; 32],
        }

        let req = CheckPreKeysRequest {
            identity_type: service_id_kind.to_string(),
            digest,
        };

        let res = self
            .http_request(Method::POST, "/v2/keys/check")?
            .send_json(&req)
            .await?;

        if res.status_code() == Some(reqwest::StatusCode::CONFLICT) {
            return Ok(false);
        }

        res.service_error_for_status().await?;

        Ok(true)
    }

    pub async fn register_pre_keys(
        &mut self,
        service_id_kind: ServiceIdKind,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        self.http_request(
            Method::PUT,
            format!("/v2/keys?identity={}", service_id_kind),
        )?
        .send_json(&pre_key_state)
        .await?
        .service_error_for_status()
        .await?;

        Ok(())
    }

    pub async fn get_pre_key(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<PreKeyBundle, ServiceError> {
        let path = format!(
            "/v2/keys/{}/{}",
            destination.service_id_string(),
            device_id
        );

        let mut pre_key_response: PreKeyResponse = self
            .http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        assert!(!pre_key_response.devices.is_empty());

        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        let device = pre_key_response.devices.remove(0);
        device.into_bundle(identity)
    }

    pub(crate) async fn get_pre_keys(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let path = if device_id == *DEFAULT_DEVICE_ID {
            format!("/v2/keys/{}/*", destination.service_id_string())
        } else {
            format!(
                "/v2/keys/{}/{}",
                destination.service_id_string(),
                device_id
            )
        };
        let pre_key_response: PreKeyResponse = self
            .http_request(Method::GET, path)?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        let mut pre_keys = vec![];
        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        for device in pre_key_response.devices {
            pre_keys.push(device.into_bundle(identity)?);
        }
        Ok(pre_keys)
    }

    pub async fn get_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .http_request(Method::GET, "/v1/certificate/delivery")?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    pub async fn get_uuid_only_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let cert: SenderCertificateJson = self
            .http_request(
                Method::GET,
                "/v1/certificate/delivery?includeE164=false",
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;
        Ok(SenderCertificate::deserialize(&cert.certificate)?)
    }

    pub async fn distribute_pni_keys(
        &mut self,
        pni_identity_key: &IdentityKey,
        device_messages: Vec<OutgoingPushMessage>,
        device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
        device_pni_last_resort_kyber_prekeys: HashMap<
            String,
            KyberPreKeyEntity,
        >,
        pni_registration_ids: HashMap<String, u32>,
        signature_valid_on_each_signed_pre_key: bool,
    ) -> Result<VerifyAccountResponse, ServiceError> {
        #[derive(serde::Serialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct PniKeyDistributionRequest {
            #[serde(with = "serde_base64")]
            pni_identity_key: Vec<u8>,
            device_messages: Vec<OutgoingPushMessage>,
            device_pni_signed_prekeys: HashMap<String, SignedPreKeyEntity>,
            #[serde(rename = "devicePniPqLastResortPrekeys")]
            device_pni_last_resort_kyber_prekeys:
                HashMap<String, KyberPreKeyEntity>,
            pni_registration_ids: HashMap<String, u32>,
            signature_valid_on_each_signed_pre_key: bool,
        }
        self.http_request(
            Method::PUT,
            "/v2/accounts/phone_number_identity_key_distribution",
        )?
        .send_json(&PniKeyDistributionRequest {
            pni_identity_key: pni_identity_key.serialize().into(),
            device_messages,
            device_pni_signed_prekeys,
            device_pni_last_resort_kyber_prekeys,
            pni_registration_ids,
            signature_valid_on_each_signed_pre_key,
        })
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
    }
}
