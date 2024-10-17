use std::collections::HashMap;

use libsignal_protocol::{IdentityKey, PreKeyBundle, SenderCertificate};
use reqwest::Method;
use serde::Deserialize;

use crate::{
    configuration::Endpoint,
    pre_keys::{KyberPreKeyEntity, PreKeyState, SignedPreKeyEntity},
    push_service::PreKeyResponse,
    sender::OutgoingPushMessage,
    utils::serde_base64,
    ServiceAddress,
};

use super::{
    response::ReqwestExt, HttpAuthOverride, PushService, SenderCertificateJson,
    ServiceError, ServiceIdType, VerifyAccountResponse,
};

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PreKeyStatus {
    pub count: u32,
    pub pq_count: u32,
}

impl PushService {
    pub async fn get_pre_key_status(
        &mut self,
        service_id_type: ServiceIdType,
    ) -> Result<PreKeyStatus, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::Service,
            &format!("/v2/keys?identity={}", service_id_type),
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

    pub async fn register_pre_keys(
        &mut self,
        service_id_type: ServiceIdType,
        pre_key_state: PreKeyState,
    ) -> Result<(), ServiceError> {
        self.request(
            Method::PUT,
            Endpoint::Service,
            &format!("/v2/keys?identity={}", service_id_type),
            HttpAuthOverride::NoOverride,
        )?
        .json(&pre_key_state)
        .send()
        .await?
        .service_error_for_status()
        .await?;

        Ok(())
    }

    pub async fn get_pre_key(
        &mut self,
        destination: &ServiceAddress,
        device_id: u32,
    ) -> Result<PreKeyBundle, ServiceError> {
        let path =
            format!("/v2/keys/{}/{}?pq=true", destination.uuid, device_id);

        let mut pre_key_response: PreKeyResponse = self
            .request(
                Method::GET,
                Endpoint::Service,
                &path,
                HttpAuthOverride::NoOverride,
            )?
            .send()
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await?;

        assert!(!pre_key_response.devices.is_empty());

        let identity = IdentityKey::decode(&pre_key_response.identity_key)?;
        let device = pre_key_response.devices.remove(0);
        Ok(device.into_bundle(identity)?)
    }

    pub(crate) async fn get_pre_keys(
        &mut self,
        destination: &ServiceAddress,
        device_id: u32,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let path = if device_id == 1 {
            format!("/v2/keys/{}/*?pq=true", destination.uuid)
        } else {
            format!("/v2/keys/{}/{}?pq=true", destination.uuid, device_id)
        };
        let pre_key_response: PreKeyResponse = self
            .request(
                Method::GET,
                Endpoint::Service,
                &path,
                HttpAuthOverride::NoOverride,
            )?
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
            .request(
                Method::GET,
                Endpoint::Service,
                "/v1/certificate/delivery",
                HttpAuthOverride::NoOverride,
            )?
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
            .request(
                Method::GET,
                Endpoint::Service,
                "/v1/certificate/delivery?includeE164=false",
                HttpAuthOverride::NoOverride,
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
        self.request(
            Method::PUT,
            Endpoint::Service,
            "/v2/accounts/phone_number_identity_key_distribution",
            HttpAuthOverride::NoOverride,
        )?
        .json(&PniKeyDistributionRequest {
            pni_identity_key: pni_identity_key.serialize().into(),
            device_messages,
            device_pni_signed_prekeys,
            device_pni_last_resort_kyber_prekeys,
            pni_registration_ids,
            signature_valid_on_each_signed_pre_key,
        })
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }
}
