use reqwest::{Method, RequestBuilder};

use crate::{
    configuration::Endpoint, content::ServiceError,
    push_service::HttpAuthOverride, websocket::SignalWebSocket,
};

impl SignalWebSocket {
    pub fn http_request(
        &self,
        method: Method,
        endpoint: Endpoint,
        auth_override: HttpAuthOverride,
    ) -> Result<RequestBuilder, ServiceError> {
        todo!();
    }
}
