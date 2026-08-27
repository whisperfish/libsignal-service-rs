//! Flatline deployment configuration.
//!
//! Flatline is a self-hosted Signal-compatible server stack reachable at
//! `*.<hostname>` (default `<hostname>` = `flatline.internal`), with TLS
//! terminated by Traefik using a pinned dev CA. This module builds the
//! [`ServiceConfiguration`] a client needs to talk to it.
//!
//! Two entry points:
//! - [`FlatlineOptions::from_env`] / [`From<FlatlineOptions>`] for a static,
//!   known Flatline deployment (embedded dev CA + pinned dev zkgroup params,
//!   base hostname from env). Matches plan acceptance: "register against a
//!   live instance given only CA path + hostname from the environment".
//! - [`from_broker_client_config`] for a Flatline CI *broker*-allocated
//!   ephemeral instance, whose CA, hostname, and zkgroup params are all
//!   per-instance and returned in `client_config`. The harness crate is the
//!   intended caller; this crate takes the broker's string fields verbatim
//!   so it needs no dependency on the broker crate.
//!
//! Not a [`crate::configuration::SignalServers`] variant: Flatline isn't a
//! `libsignal_net::env`, so CDSI contact discovery is unavailable on a
//! configuration built here.

use std::collections::HashMap;
use std::path::Path;

use base64::prelude::*;
use libsignal_protocol::PublicKey;
use url::Url;
use zkgroup::ServerPublicParams;

use crate::configuration::ServiceConfiguration;
use crate::utils::BASE64_RELAXED;

/// Flatline dev zkgroup server public params, pinned in
/// `charts/flatline/files/whisper-service/dev.yml` (`zkConfig.serverPublic`).
const ZKGROUP_SERVER_PUBLIC_PARAMS: &str = "AAK51fKwiJcO4RksMY2NX9xgiYf2QAITLffSjPru/jRgMoq7H9g2lRsmWmg9tZLY0deP9bb/dd9DyGRBEXuZFxucayWQKBT96ZphTtMrw1451atuth13eaJuiYh66wpoZtDp12omXr33bWfcnw3tQIt/E902+BFo0Jxq4yvj1xNu6gkXRoKejLx+TNiZV9uJbe5PWG9ZveFvCbs1NbGrjG84Px9qzSZoDwpgW+s1g9cC97x7J91HL9COthgus2FAd1pJPucej4KQVAHDo6XJ8QfRX5iwhs6p0IUX57aI4H0RUsk0KhJxM8xyXaEg6WsIQ7fYk187AjfEDio5CCmRKkCKoBUfuP5UiDsyo0mIQhS5xv0f78VF6V7ELfcXkbjQHJ6aryweshNHyRPyIjPEW62cVgjOAhYtC2VfBhOD2MYy3h0TPaXPOvXqonhT4kSIAO5RfH+hBvWtAE1wnauki2bmvESqmUXkgAI5cd2v26O3W3EnTaQofkT9O9zpTsKcQ5ipLGrrGNWakCMgmr0sOpIHUZLbobruqKdeLnY+ootB4N70oZOUsQ1SQqjLqNri3fk8iGt92SXxVk154zs8Unaszg1ZkfMOI6Ik5+YysB+g/eGg3zDf3qBt1sNZAtNlHYRvMGPkGG5RExm8BMAsC6XTAdDOLljmaUoZKKsnI+Iq8Lx8ZEbtgBmwRpEn++n20TkoMwmdaD/Koq8iSXoPHWP+p9Pkiw8oYrQ6s6F9JSJLB/qwbbNak4EuSS/JSrtODrzC1oEjD24xq1U5j7yU61u2tmVy67z22sEzQufS5LVU2Ff379UZq0E7KIRFXn6OyjIrzyb+TsEHidib5hyxVGhw02lrL4AseV9mgFUgrd8bkWLhLtuAKXI6kIN4YejVAQ==";

/// Flatline dev CA PEM, the wildcard `*.<hostname>` trust root from
/// `charts/flatline/files/traefik/ca.pem`.
const DEV_CA_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certs/flatline-dev-ca.pem"
));

/// Options for building a Flatline [`ServiceConfiguration`].
#[derive(Debug, Clone)]
pub struct FlatlineOptions {
    /// Base hostname clients use to reach Flatline (e.g. `flatline.internal`).
    pub hostname: String,
    /// PEM-encoded CA certificate that signed the Flatline wildcard cert.
    pub ca_pem: String,
}

impl FlatlineOptions {
    /// Read Flatline options from the environment.
    ///
    /// - `FLATLINE_HOSTNAME`: base hostname (defaults to `flatline.internal`).
    /// - `FLATLINE_CA_PATH`: path to a CA PEM file. When unset, the embedded
    ///   Flatline dev CA is used.
    pub fn from_env() -> std::io::Result<Self> {
        let hostname = std::env::var("FLATLINE_HOSTNAME")
            .unwrap_or_else(|_| "flatline.internal".to_string());
        let ca_pem = match std::env::var("FLATLINE_CA_PATH") {
            Ok(path) => std::fs::read_to_string(Path::new(&path))?,
            Err(_) => DEV_CA_PEM.to_string(),
        };
        Ok(Self { hostname, ca_pem })
    }
}

impl From<FlatlineOptions> for ServiceConfiguration {
    fn from(opts: FlatlineOptions) -> Self {
        let https = |sub: &str| -> Url {
            format!("https://{}.{}", sub, opts.hostname)
                .parse()
                .expect("valid Flatline URL")
        };

        // CDN id mapping mirrors the Signal presets; Flatline only serves
        // cdn0 and cdn3 (see charts/flatline/templates/traefik.yaml).
        let cdn_urls = [(0u32, https("cdn0")), (3, https("cdn3"))]
            .into_iter()
            .collect();

        let zkgroup_server_public_params =
            decode_zkgroup_params(ZKGROUP_SERVER_PUBLIC_PARAMS)
                .expect("pinned Flatline zkgroup params");

        ServiceConfiguration::new(
            https("whisper"),
            https("storage"),
            cdn_urls,
            opts.ca_pem,
            // Unidentified-sender trust roots are not needed for registration;
            // deriving them from the Flatline unidentified delivery secret is
            // a follow-up.
            Vec::<PublicKey>::new(),
            zkgroup_server_public_params,
        )
    }
}

/// Errors building a [`ServiceConfiguration`] from a broker `client_config`.
#[derive(Debug, thiserror::Error)]
pub enum FlatlineConfigError {
    #[error("invalid {field} URL: {source}")]
    InvalidUrl {
        field: &'static str,
        #[source]
        source: url::ParseError,
    },
    #[error("invalid CDN id {0:?}")]
    InvalidCdnId(String),
    #[error("invalid zkgroup server public params: {0}")]
    InvalidZkgroupParams(String),
}

/// Decode the base64 (bincode) string the broker forwards from the chart's
/// `dev.yml` (`zkConfig.serverPublic`) into [`ServerPublicParams`].
fn decode_zkgroup_params(b64: &str) -> Result<ServerPublicParams, String> {
    if b64.is_empty() {
        // Broker deployments that haven't set FLATLINE_ZKGROUP_PUBLIC_PARAMS
        // forward an empty string. Fall back to the pinned Flatline dev params
        // (charts/flatline/files/whisper-service/dev.yml) — the broker's
        // deployed chart uses exactly those.
        return decode_zkgroup_params(ZKGROUP_SERVER_PUBLIC_PARAMS);
    }
    let bytes = BASE64_RELAXED
        .decode(b64)
        .map_err(|e| format!("base64: {e}"))?;
    bincode::deserialize(&bytes).map_err(|e| format!("bincode: {e}"))
}

/// Build a [`ServiceConfiguration`] from a Flatline CI broker `client_config`
/// object.
///
/// The broker (`flatline-harness`) allocates an ephemeral instance whose CA,
/// per-instance hostname (`i-<id>.flatline.internal`), and zkgroup params are
/// all minted/pinned per allocation and returned in `client_config`. This is
/// the seam the harness crate calls to hand those to `PushService::from_config`;
/// this crate takes the broker's string fields verbatim so it has no dependency
/// on the broker crate.
///
/// `zkgroup_server_public_params` is the base64 (bincode) string the broker
/// forwards from the chart's `dev.yml`. Trust roots are left empty —
/// registration does not need them.
pub fn from_broker_client_config(
    service_url: &str,
    storage_url: &str,
    cdn_urls: &HashMap<String, String>,
    ca_pem: impl Into<String>,
    zkgroup_server_public_params: &str,
) -> Result<ServiceConfiguration, FlatlineConfigError> {
    let service_url = service_url.parse().map_err(|source| {
        FlatlineConfigError::InvalidUrl {
            field: "service_url",
            source,
        }
    })?;
    let storage_url = storage_url.parse().map_err(|source| {
        FlatlineConfigError::InvalidUrl {
            field: "storage_url",
            source,
        }
    })?;

    let mut cdn = HashMap::with_capacity(cdn_urls.len());
    for (k, v) in cdn_urls {
        let id: u32 = k
            .parse()
            .map_err(|_| FlatlineConfigError::InvalidCdnId(k.clone()))?;
        let url: Url =
            v.parse()
                .map_err(|source| FlatlineConfigError::InvalidUrl {
                    field: "cdn_urls",
                    source,
                })?;
        cdn.insert(id, url);
    }

    let zkgroup_server_public_params =
        decode_zkgroup_params(zkgroup_server_public_params)
            .map_err(FlatlineConfigError::InvalidZkgroupParams)?;

    Ok(ServiceConfiguration::new(
        service_url,
        storage_url,
        cdn,
        ca_pem,
        Vec::<PublicKey>::new(),
        zkgroup_server_public_params,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_broker_client_config_parses_dev_values() {
        let mut cdn = HashMap::new();
        cdn.insert(
            "0".to_string(),
            "https://cdn0.i-abc.flatline.internal".to_string(),
        );
        cdn.insert(
            "3".to_string(),
            "https://cdn3.i-abc.flatline.internal".to_string(),
        );

        let ca_pem =
            "-----BEGIN CERTIFICATE-----\ndev\n-----END CERTIFICATE-----\n";
        let cfg = from_broker_client_config(
            "https://whisper.i-abc.flatline.internal",
            "https://storage.i-abc.flatline.internal",
            &cdn,
            ca_pem,
            ZKGROUP_SERVER_PUBLIC_PARAMS,
        )
        .expect("dev values parse");

        assert_eq!(cfg.service_url().scheme(), "https");
        assert_eq!(
            cfg.service_url().host_str(),
            Some("whisper.i-abc.flatline.internal"),
        );
        assert_eq!(cfg.storage_url().scheme(), "https");
        assert_eq!(
            cfg.storage_url().host_str(),
            Some("storage.i-abc.flatline.internal"),
        );
        assert_eq!(cfg.cdn_urls().len(), 2);
        assert_eq!(
            cfg.cdn_urls().get(&0).unwrap().host_str(),
            Some("cdn0.i-abc.flatline.internal"),
        );
        assert_eq!(cfg.certificate_authority, ca_pem);
    }

    #[test]
    fn from_broker_client_config_rejects_bad_cdn_id() {
        let mut cdn = HashMap::new();
        cdn.insert("not-a-u32".to_string(), "https://cdn0.x/".to_string());
        let err = from_broker_client_config(
            "https://whisper.x/",
            "https://storage.x/",
            &cdn,
            "ca",
            ZKGROUP_SERVER_PUBLIC_PARAMS,
        )
        .err()
        .unwrap();
        assert!(matches!(err, FlatlineConfigError::InvalidCdnId(_)));
    }

    #[test]
    fn from_broker_client_config_rejects_bad_zkgroup() {
        let cdn = HashMap::new();
        let err = from_broker_client_config(
            "https://whisper.x/",
            "https://storage.x/",
            &cdn,
            "ca",
            "not-base64-at-all!!!",
        )
        .err()
        .unwrap();
        assert!(matches!(err, FlatlineConfigError::InvalidZkgroupParams(_)));
    }
}
