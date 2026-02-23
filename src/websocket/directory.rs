//! Contact Discovery Service (CDSI) authentication
//!
//! Provides authentication credentials for CDSI contact lookup operations.
//!
use libsignal_core::ServiceId;
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
use crate::utils::TryIntoE164;
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

    /// Resolve phone numbers (with possible extra information) to accounts.
    ///
    /// Uses Contact Discovery Service (CDSI) via libsignal-net. The phone numbers
    /// are looked up inside an SGX enclave for privacy.
    ///
    /// # Arguments
    /// * `lookup_request` - The CDSI lookup request containing phone numbers and other parameters
    ///
    /// # Returns
    /// * `Ok(Vec<Option<ServiceId>>)` - Vector of resolved ServiceIds (None if not found)
    /// * `Err(ServiceError)` - Network or protocol error
    pub async fn discover_contacts(
        &mut self,
        lookup_request: LookupRequest,
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

    /// Resolve a single phone number (E.164 format, e.g., "+15551234567") to a ServiceId.
    ///
    /// Convenience wrapper that looks up a single phone number using CDSI.
    ///
    /// # Arguments
    /// * `phone_number` - Phone number in E.164 format (e.g., "+15551234567")
    ///
    /// # Returns
    /// * `Ok(Option<ServiceId>)` - The resolved ServiceId (None if not found)
    /// * `Err(ServiceError)` - Network or protocol error
    pub async fn discover_contact_by_phone_number(
        &mut self,
        phone_number: impl TryIntoE164,
    ) -> Result<Option<ServiceId>, ServiceError> {
        let lookup_request = LookupRequest {
            new_e164s: vec![phone_number
                .try_into_e164()
                .map_err(|_| ServiceError::InvalidPhoneNumber)?],
            ..Default::default()
        };

        let results = self.discover_contacts(lookup_request).await?;
        Ok(results.into_iter().next().flatten())
    }
}
