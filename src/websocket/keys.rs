use std::collections::HashMap;

use libsignal_core::DeviceId;
use libsignal_protocol::{
    kem::{Key, Public},
    IdentityKey, PreKeyBundle, PublicKey, SenderCertificate, ServiceId,
    ServiceIdKind,
};
use reqwest::Method;

use crate::{
    pre_keys::{
        KyberPreKeyEntity, PreKeyEntity, PreKeyState, SignedPreKeyEntity,
    },
    push_service::response::SignalServiceResponse,
    push_service::DEFAULT_DEVICE_ID,
    sender::OutgoingPushMessage,
    utils::serde_base64,
    websocket::{self, registration::VerifyAccountResponse, SignalWebSocket},
};

use libsignal_net_grpc::proto::chat::{
    common::{EcPreKey, EcSignedPreKey, IdentityType, KemSignedPreKey},
    credentials::{
        credentials_client::CredentialsClient, GetDeliveryCertificateRequest,
        GetDeliveryCertificateResponse,
    },
    keys::{
        get_pre_keys_response, keys_client::KeysClient, AccountPreKeyBundles,
        DevicePreKeyBundle, GetPreKeyCountRequest, GetPreKeysRequest,
        SetEcSignedPreKeyRequest, SetKemLastResortPreKeyRequest,
        SetOneTimeEcPreKeysRequest, SetOneTimeKemSignedPreKeysRequest,
    },
};

use super::ServiceError;

#[derive(Debug, Default)]
pub struct PreKeyStatus {
    pub count: u32,
    pub pq_count: u32,
}

impl SignalWebSocket<websocket::Identified> {
    pub async fn get_pre_key_status(
        &mut self,
        service_id_kind: ServiceIdKind,
    ) -> Result<PreKeyStatus, ServiceError> {
        let counts = KeysClient::new(self.grpc.authenticated()?)
            .get_pre_key_count(GetPreKeyCountRequest {})
            .await?
            .into_inner();
        Ok(match service_id_kind {
            ServiceIdKind::Aci => PreKeyStatus {
                count: counts.aci_ec_pre_key_count,
                pq_count: counts.aci_kem_pre_key_count,
            },
            ServiceIdKind::Pni => PreKeyStatus {
                count: counts.pni_ec_pre_key_count,
                pq_count: counts.pni_kem_pre_key_count,
            },
        })
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
        let identity_type = match service_id_kind {
            ServiceIdKind::Aci => IdentityType::Aci,
            ServiceIdKind::Pni => IdentityType::Pni,
        }
        .into();
        let PreKeyState {
            pre_keys,
            signed_pre_key,
            identity_key: _,
            pq_last_resort_key,
            pq_pre_keys,
        } = pre_key_state;
        let mut keys = KeysClient::new(self.grpc.authenticated()?);

        if !pre_keys.is_empty() {
            keys.set_one_time_ec_pre_keys(SetOneTimeEcPreKeysRequest {
                identity_type,
                pre_keys: pre_keys
                    .into_iter()
                    .map(
                        |PreKeyEntity {
                             key_id: id,
                             public_key,
                         }| {
                            Ok(EcPreKey {
                                key_id: key_id(id)?,
                                public_key,
                            })
                        },
                    )
                    .collect::<Result<_, ServiceError>>()?,
            })
            .await?;
        }

        let SignedPreKeyEntity {
            key_id: signed_key_id,
            public_key,
            signature,
        } = signed_pre_key;
        keys.set_ec_signed_pre_key(SetEcSignedPreKeyRequest {
            identity_type,
            signed_pre_key: Some(EcSignedPreKey {
                key_id: key_id(signed_key_id)?,
                public_key,
                signature,
            }),
        })
        .await?;

        if let Some(KyberPreKeyEntity {
            key_id: last_resort_key_id,
            public_key,
            signature,
        }) = pq_last_resort_key
        {
            keys.set_kem_last_resort_pre_key(SetKemLastResortPreKeyRequest {
                identity_type,
                signed_pre_key: Some(KemSignedPreKey {
                    key_id: key_id(last_resort_key_id)?,
                    public_key,
                    signature,
                }),
            })
            .await?;
        }

        if !pq_pre_keys.is_empty() {
            keys.set_one_time_kem_signed_pre_keys(
                SetOneTimeKemSignedPreKeysRequest {
                    identity_type,
                    pre_keys: pq_pre_keys
                        .into_iter()
                        .map(
                            |KyberPreKeyEntity {
                                 key_id: id,
                                 public_key,
                                 signature,
                             }| {
                                Ok(KemSignedPreKey {
                                    key_id: key_id(id)?,
                                    public_key,
                                    signature,
                                })
                            },
                        )
                        .collect::<Result<_, ServiceError>>()?,
                },
            )
            .await?;
        }

        Ok(())
    }

    pub async fn get_pre_key(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<PreKeyBundle, ServiceError> {
        self.fetch_pre_keys(destination, Some(device_id))
            .await?
            .into_iter()
            .next()
            .ok_or(ServiceError::NotFoundError)
    }

    pub(crate) async fn get_pre_keys(
        &mut self,
        destination: &ServiceId,
        device_id: DeviceId,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let device_id = (device_id != *DEFAULT_DEVICE_ID).then_some(device_id);
        self.fetch_pre_keys(destination, device_id).await
    }

    async fn fetch_pre_keys(
        &mut self,
        destination: &ServiceId,
        device_id: Option<DeviceId>,
    ) -> Result<Vec<PreKeyBundle>, ServiceError> {
        let response = KeysClient::new(self.grpc.authenticated()?)
            .get_pre_keys(GetPreKeysRequest {
                target_identifier: Some((*destination).into()),
                device_id: device_id.map(|d| u8::from(d).into()),
            })
            .await?
            .into_inner();
        match response.response {
            Some(get_pre_keys_response::Response::PreKeys(bundles)) => {
                into_bundles(bundles)
            },
            Some(get_pre_keys_response::Response::TargetNotFound(_)) => {
                Err(ServiceError::NotFoundError)
            },
            None => Err(ServiceError::InvalidFrame {
                reason: "empty GetPreKeys response",
            }),
        }
    }

    pub async fn get_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let certs = self.delivery_certificates().await?;
        Ok(SenderCertificate::deserialize(
            &certs.certificate_with_e164,
        )?)
    }

    pub async fn get_uuid_only_sender_certificate(
        &mut self,
    ) -> Result<SenderCertificate, ServiceError> {
        let certs = self.delivery_certificates().await?;
        Ok(SenderCertificate::deserialize(
            &certs.certificate_without_e164,
        )?)
    }

    async fn delivery_certificates(
        &mut self,
    ) -> Result<GetDeliveryCertificateResponse, ServiceError> {
        Ok(CredentialsClient::new(self.grpc.authenticated()?)
            .get_delivery_certificate(GetDeliveryCertificateRequest {})
            .await?
            .into_inner())
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

fn key_id(id: u32) -> Result<i32, ServiceError> {
    i32::try_from(id).map_err(|_| ServiceError::InvalidFrame {
        reason: "pre-key id out of range",
    })
}

fn into_bundles(
    bundles: AccountPreKeyBundles,
) -> Result<Vec<PreKeyBundle>, ServiceError> {
    let AccountPreKeyBundles {
        identity_key,
        device_pre_keys,
        unrestricted_unidentified_access: _,
        unidentified_access_key_fingerprint: _,
    } = bundles;
    let identity = IdentityKey::decode(&identity_key)?;
    let mut devices: Vec<_> = device_pre_keys.into_iter().collect();
    devices.sort_by_key(|(id, _)| *id);
    devices
        .into_iter()
        .map(|(device_id, bundle)| into_bundle(device_id, bundle, identity))
        .collect()
}

fn into_bundle(
    device_id: u32,
    bundle: DevicePreKeyBundle,
    identity: IdentityKey,
) -> Result<PreKeyBundle, ServiceError> {
    const INVALID: ServiceError = ServiceError::InvalidFrame {
        reason: "invalid pre-key bundle",
    };
    let DevicePreKeyBundle {
        ec_signed_pre_key,
        ec_one_time_pre_key,
        kem_one_time_pre_key,
        registration_id,
    } = bundle;
    let EcSignedPreKey {
        key_id: signed_key_id,
        public_key: signed_public_key,
        signature: signed_signature,
    } = ec_signed_pre_key.ok_or(INVALID)?;
    let KemSignedPreKey {
        key_id: kem_key_id,
        public_key: kem_public_key,
        signature: kem_signature,
    } = kem_one_time_pre_key.ok_or(INVALID)?;
    let one_time = ec_one_time_pre_key
        .map(
            |EcPreKey { key_id, public_key }| -> Result<_, ServiceError> {
                Ok((
                    u32::try_from(key_id).map_err(|_| INVALID)?.into(),
                    PublicKey::deserialize(&public_key)?,
                ))
            },
        )
        .transpose()?;
    Ok(PreKeyBundle::new(
        registration_id,
        DeviceId::try_from(device_id)?,
        one_time,
        u32::try_from(signed_key_id).map_err(|_| INVALID)?.into(),
        PublicKey::deserialize(&signed_public_key)?,
        signed_signature,
        u32::try_from(kem_key_id).map_err(|_| INVALID)?.into(),
        Key::<Public>::deserialize(&kem_public_key)?,
        kem_signature,
        identity,
    )?)
}
