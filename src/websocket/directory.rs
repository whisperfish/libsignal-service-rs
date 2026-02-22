//! Contact Discovery Service (CDSI) authentication
//!
//! Provides authentication credentials for CDSI contact lookup operations.

use libsignal_core::{E164, ServiceId};
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{CdsiConnection, LookupRequest};
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG,
};
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::utils::no_network_change_events;
use reqwest::Method;
use serde::Deserialize;
use tracing::warn;

use crate::content::ServiceError;
use crate::websocket::{Identified, SignalWebSocket};

/// CDSI authentication credentials
#[derive(Debug, Deserialize)]
struct CdsiAuth {
    pub username: String,
    pub password: String,
}

impl SignalWebSocket<Identified> {
    /// Get CDSI authentication credentials from the chat server.
    ///
    /// Returns username/password credentials for establishing an
    /// authenticated connection to the Contact Discovery Service.
    ///
    /// # Returns
    /// * `Ok(CdsiAuth)` - Authentication credentials
    /// * `Err(ServiceError)` - Network or protocol error
    ///
    /// # Example
    /// ```no_run
    /// # use libsignal_service::websocket::{SignalWebSocket, Identified};
    /// # async fn example(mut ws: SignalWebSocket<Identified>) {
    /// let auth = ws.get_cdsi_auth().await.unwrap();
    /// // Use auth.username and auth.password for CDSI connection
    /// # }
    /// ```
    async fn get_cdsi_auth(&mut self) -> Result<CdsiAuth, ServiceError> {
        let response = self
            .http_request(Method::GET, "/v2/directory/auth")?
            .send()
            .await?
            .service_error_for_status()
            .await?;

        response.json().await
    }

    /// Resolve a phone number (E.164 format, e.g., "+15551234567") to an ACI.
    ///
    /// Uses Contact Discovery Service (CDSI) via libsignal-net. The phone number
    /// is looked up inside an SGX enclave for privacy.
    pub async fn resolve_phone_number(
        &mut self,
        phone_numbers: impl IntoIterator<Item = E164>,
    ) -> Result<Vec<Option<ServiceId>>, ServiceError> {
        let env: libsignal_net::env::Env<'_> = self.servers().into();

        // 1. Get CDSI auth credentials from chat server
        let cdsi_auth_response = self.get_cdsi_auth().await?;

        let auth = Auth {
            username: cdsi_auth_response.username,
            password: cdsi_auth_response.password,
        };

        // 2. Set up connection infrastructure
        let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
        let network_change_event = no_network_change_events();
        let static_map = std::collections::HashMap::from([env
            .cdsi
            .domain_config
            .static_fallback(libsignal_net::env::StaticIpOrder::HARDCODED)]);
        let dns_resolver = DnsResolver::new_with_static_fallback(
            static_map,
            &network_change_event,
        );

        let connection_resources = ConnectionResources {
            connect_state: &connect_state,
            dns_resolver: &dns_resolver,
            network_change_event: &network_change_event,
            confirmation_header_name: None,
        };

        // 3. Connect to CDSI using DirectOrProxyProvider::direct() wrapper
        let cdsi_endpoint = &env.cdsi;
        let cdsi_connection = CdsiConnection::connect_with(
            connection_resources,
            libsignal_net_infra::route::DirectOrProxyProvider::direct(
                cdsi_endpoint.enclave_websocket_provider(
                    libsignal_net_infra::EnableDomainFronting::No,
                ),
            ),
            cdsi_endpoint.ws_config,
            &cdsi_endpoint.params,
            &auth,
        )
        .await?;

        // 4. Send lookup request
        let lookup_request = LookupRequest {
            new_e164s: phone_numbers.into_iter().collect(),
            ..Default::default()
        };
        let (_token, collector) =
            cdsi_connection.send_request(lookup_request).await?;
        let response = collector.collect().await?;

        Ok(response.records.into_iter().map(|r| match (r.pni, r.aci) {
            (None, None) => None,
            (None, Some(aci)) => Some(aci.into()),
            (Some(pni), None) => Some(pni.into()),
            (Some(_), Some(aci)) => {
                warn!("got both ACI and PNI for a phone number, this is unexpected, using ACI!");
                Some(aci.into())
            },
        }).collect())
    }
}
