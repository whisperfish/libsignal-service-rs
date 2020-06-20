use std::{sync::Arc, time::Duration};

use awc::Connector;
use libsignal_service::{configuration::*, push_service::*};
use serde::Deserialize;
use url::Url;

pub struct AwcPushService {
    cfg: ServiceConfiguration,
    base_url: Url,
    client: awc::Client,
}

#[async_trait::async_trait(?Send)]
impl PushService for AwcPushService {
    async fn get<T>(&mut self, path: &str) -> Result<T, ServiceError>
    where
        for<'de> T: Deserialize<'de>,
    {
        // In principle, we should be using http::uri::Uri,
        // but that doesn't seem like an owned type where we can do this kind of
        // constructions on.
        // https://docs.rs/http/0.2.1/http/uri/struct.Uri.html
        let url = self.base_url.join(path).expect("valid url");

        log::debug!("AwcPushService::get({:?})", url);
        let mut response =
            self.client.get(url.as_str()).send().await.map_err(|e| {
                ServiceError::SendError {
                    reason: e.to_string(),
                }
            })?;

        log::debug!("AwcPushService::get response: {:?}", response);

        ServiceError::from_status(response.status())?;

        // In order to debug the output, we collect the whole response.
        // The actix-web api is meant to used as a streaming deserializer,
        // so we have this little awkward switch.
        //
        // This is also the reason we depend directly on serde_json, however
        // actix already imports that anyway.
        if log::log_enabled!(log::Level::Debug) {
            let text = response.body().await.map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })?;
            log::debug!("GET response: {:?}", String::from_utf8_lossy(&text));
            serde_json::from_slice(&text).map_err(|e| {
                ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                }
            })
        } else {
            response
                .json()
                .await
                .map_err(|e| ServiceError::JsonDecodeError {
                    reason: e.to_string(),
                })
        }
    }
}

impl AwcPushService {
    /// Creates a new AwcPushService
    ///
    /// Panics on invalid service url.
    pub fn new(
        cfg: ServiceConfiguration,
        credentials: Credentials,
        user_agent: &str,
        root_ca: &str,
    ) -> Self {
        let base_url =
            Url::parse(&cfg.service_urls[0]).expect("valid service url");

        // SSL setup
        let mut ssl_config = rustls::ClientConfig::new();
        ssl_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        ssl_config
            .root_store
            .add_pem_file(&mut std::io::Cursor::new(root_ca))
            .unwrap();
        let connector = Connector::new()
                    .rustls(Arc::new(ssl_config))
                    .timeout(Duration::from_secs(10)) // https://github.com/actix/actix-web/issues/1047
                    .finish();
        let client = awc::ClientBuilder::new()
            .connector(connector)
            .header("X-Signal-Agent", user_agent)
            .timeout(Duration::from_secs(65)); // as in Signal-Android

        let client = if let Some((ident, pass)) = credentials.authorization() {
            client.basic_auth(ident, Some(pass))
        } else {
            client
        };
        let client = client.finish();

        Self {
            cfg,
            base_url,
            client,
        }
    }
}
