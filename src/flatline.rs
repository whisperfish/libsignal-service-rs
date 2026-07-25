//! Flatline deployment configuration.
//!
//! Flatline is a self-hosted Signal-compatible server stack reachable at
//! `*.<hostname>` (default `<hostname>` = `flatline.internal`), with TLS
//! terminated by Traefik using a pinned dev CA. This module builds the
//! [`ServiceConfiguration`] a client needs to talk to it.
//!
//! This is the seam a test harness uses to register accounts against Flatline.
//! Only what registration needs is wired up: the chat/storage/CDN URLs and the
//! dev CA. The zkgroup server public params are the pinned Flatline dev values
//! from `charts/flatline/files/whisper-service/dev.yml`; trust roots for
//! unidentified delivery are left empty — registration does not need them.
//!
//! Not a [`crate::configuration::SignalServers`] variant: Flatline isn't a
//! `libsignal_net::env`, so CDSI contact discovery is unavailable on a
//! configuration built here.

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

        let zkgroup_server_public_params: ServerPublicParams =
            bincode::deserialize(
                &BASE64_RELAXED
                    .decode(ZKGROUP_SERVER_PUBLIC_PARAMS)
                    .expect("pinned Flatline zkgroup params decode"),
            )
            .expect("pinned Flatline zkgroup params deserialize");

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
