use reqwest::StatusCode;

use crate::proto::WebSocketResponseMessage;

use super::ServiceError;

pub(crate) async fn service_error_for_status<R>(
    response: R,
) -> Result<R, ServiceError>
where
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    match response.status_code() {
        StatusCode::OK
        | StatusCode::CREATED
        | StatusCode::ACCEPTED
        | StatusCode::NO_CONTENT => Ok(response),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(ServiceError::Unauthorized)
        },
        StatusCode::NOT_FOUND => {
            // This is 404 and means that e.g. recipient is not registered
            Err(ServiceError::NotFoundError)
        },
        StatusCode::PAYLOAD_TOO_LARGE => {
            // This is 413 and means rate limit exceeded for Signal.
            Err(ServiceError::RateLimitExceeded)
        },
        StatusCode::CONFLICT => {
            let mismatched_devices =
                response.json().await.map_err(|error| {
                    tracing::error!(
                        %error,
                        "failed to decode HTTP 409 status"
                    );
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::CONFLICT.as_u16(),
                    }
                })?;
            Err(ServiceError::MismatchedDevicesException(mismatched_devices))
        },
        StatusCode::GONE => {
            let stale_devices = response.json().await.map_err(|error| {
                tracing::error!(%error, "failed to decode HTTP 410 status");
                ServiceError::UnhandledResponseCode {
                    http_code: StatusCode::GONE.as_u16(),
                }
            })?;
            Err(ServiceError::StaleDevices(stale_devices))
        },
        StatusCode::LOCKED => {
            let locked = response.json().await.map_err(|error| {
                tracing::error!(%error, "failed to decode HTTP 423 status");
                ServiceError::UnhandledResponseCode {
                    http_code: StatusCode::LOCKED.as_u16(),
                }
            })?;
            Err(ServiceError::Locked(locked))
        },
        StatusCode::PRECONDITION_REQUIRED => {
            let proof_required = response.json().await.map_err(|error| {
                tracing::error!(
                    %error,
                    "failed to decode HTTP 428 status"
                );
                ServiceError::UnhandledResponseCode {
                    http_code: StatusCode::PRECONDITION_REQUIRED.as_u16(),
                }
            })?;
            Err(ServiceError::ProofRequiredError(proof_required))
        },
        // XXX: fill in rest from PushServiceSocket
        code => {
            let response_text = response.text().await?;
            tracing::trace!(status_code =% code, body = response_text, "unhandled HTTP response");
            Err(ServiceError::UnhandledResponseCode {
                http_code: code.as_u16(),
            })
        },
    }
}

#[async_trait::async_trait]
pub(crate) trait SignalServiceResponse {
    type Error: std::error::Error;

    fn status_code(&self) -> StatusCode;

    async fn json<U>(self) -> Result<U, Self::Error>
    where
        for<'de> U: serde::Deserialize<'de>;

    async fn text(self) -> Result<String, Self::Error>;
}

#[async_trait::async_trait]
impl SignalServiceResponse for reqwest::Response {
    type Error = reqwest::Error;

    fn status_code(&self) -> StatusCode {
        self.status()
    }

    async fn json<U>(self) -> Result<U, Self::Error>
    where
        for<'de> U: serde::Deserialize<'de>,
    {
        reqwest::Response::json(self).await
    }

    async fn text(self) -> Result<String, Self::Error> {
        reqwest::Response::text(self).await
    }
}

#[async_trait::async_trait]
impl SignalServiceResponse for WebSocketResponseMessage {
    type Error = ServiceError;

    fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status() as u16).unwrap_or_default()
    }

    async fn json<U>(self) -> Result<U, Self::Error>
    where
        for<'de> U: serde::Deserialize<'de>,
    {
        serde_json::from_slice(self.body()).map_err(Into::into)
    }

    async fn text(self) -> Result<String, Self::Error> {
        Ok(self
            .body
            .map(|body| String::from_utf8_lossy(&body).to_string())
            .unwrap_or_default())
    }
}

#[async_trait::async_trait]
pub(crate) trait ReqwestExt
where
    Self: Sized,
{
    /// convenience error handler to be used in the builder-style API of `reqwest::Response`
    async fn service_error_for_status(
        self,
    ) -> Result<reqwest::Response, ServiceError>;
}

#[async_trait::async_trait]
impl ReqwestExt for reqwest::Response {
    async fn service_error_for_status(
        self,
    ) -> Result<reqwest::Response, ServiceError> {
        service_error_for_status(self).await
    }
}
