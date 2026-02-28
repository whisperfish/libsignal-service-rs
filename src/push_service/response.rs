use reqwest::StatusCode;

use crate::proto::WebSocketResponseMessage;

use super::ServiceError;

/// Handle HTTP status codes for general service operations.
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
        StatusCode::LENGTH_REQUIRED => {
            #[derive(Debug, serde::Deserialize)]
            struct LinkedDeviceNumberError {
                current: u32,
                max: u32,
            }
            let error: LinkedDeviceNumberError =
                response.json().await.map_err(|error| {
                    tracing::warn!(
                        %error,
                        "failed to decode linked device HTTP 411 status"
                    );
                    ServiceError::UnhandledResponseCode {
                        http_code: StatusCode::LENGTH_REQUIRED.as_u16(),
                    }
                })?;
            Err(ServiceError::DeviceLimitReached {
                current: error.current,
                max: error.max,
            })
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

/// Handle HTTP status codes specific to Group V2 operations.
///
/// Group operations have different semantics for some HTTP status codes:
/// - 409 Conflict: Revision conflict (client needs to rebase changes)
/// - 403 Forbidden: Insufficient permissions for group operation
/// - 404 Not Found: Group doesn't exist
/// - 410 Gone: Group has been deleted
pub(crate) async fn service_error_for_group_status<R>(
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
        StatusCode::UNAUTHORIZED => Err(ServiceError::Unauthorized),
        StatusCode::FORBIDDEN => {
            // Group operation forbidden - user lacks permissions
            Err(ServiceError::GroupForbidden)
        },
        StatusCode::NOT_FOUND => {
            // Group doesn't exist
            Err(ServiceError::GroupNotFound)
        },
        StatusCode::CONFLICT => {
            // Group revision conflict - client needs to fetch latest state and rebase
            Err(ServiceError::GroupRevisionConflict)
        },
        StatusCode::GONE => {
            // Group has been deleted
            Err(ServiceError::GroupGone)
        },
        StatusCode::PAYLOAD_TOO_LARGE => Err(ServiceError::RateLimitExceeded),
        StatusCode::LOCKED => {
            let locked = response.json().await.map_err(|error| {
                tracing::error!(%error, "failed to decode HTTP 423 status");
                ServiceError::UnhandledResponseCode {
                    http_code: StatusCode::LOCKED.as_u16(),
                }
            })?;
            Err(ServiceError::Locked(locked))
        },
        code => {
            let response_text = response.text().await?;
            tracing::trace!(status_code =% code, body = response_text, "unhandled HTTP response for group operation");
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
    /// Convenience error handler for general service operations.
    /// Use `service_error_for_group_status` for Group V2 operations.
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

#[async_trait::async_trait]
pub(crate) trait GroupServiceExt
where
    Self: Sized,
{
    /// Error handler for Group V2 operations.
    ///
    /// Handles group-specific HTTP status codes:
    /// - 409 Conflict: Revision conflict (client needs to rebase changes)
    /// - 403 Forbidden: Insufficient permissions for group operation
    /// - 404 Not Found: Group doesn't exist
    /// - 410 Gone: Group has been deleted
    async fn service_error_for_group_status(
        self,
    ) -> Result<reqwest::Response, ServiceError>;
}

#[async_trait::async_trait]
impl GroupServiceExt for reqwest::Response {
    async fn service_error_for_group_status(
        self,
    ) -> Result<reqwest::Response, ServiceError> {
        service_error_for_group_status(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    /// Mock response for testing
    #[derive(Debug)]
    struct MockResponse {
        status: StatusCode,
    }

    #[async_trait::async_trait]
    impl SignalServiceResponse for MockResponse {
        type Error = std::io::Error;

        fn status_code(&self) -> StatusCode {
            self.status
        }

        async fn json<U>(self) -> Result<U, Self::Error>
        where
            for<'de> U: serde::Deserialize<'de>,
        {
            // Return a default value for testing
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not used in these tests",
            ))
        }

        async fn text(self) -> Result<String, Self::Error> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn test_group_conflict_returns_revision_conflict_error() {
        let response = MockResponse {
            status: StatusCode::CONFLICT,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(
            result.unwrap_err(),
            ServiceError::GroupRevisionConflict
        ));
    }

    #[tokio::test]
    async fn test_group_forbidden_returns_forbidden_error() {
        let response = MockResponse {
            status: StatusCode::FORBIDDEN,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(result.unwrap_err(), ServiceError::GroupForbidden));
    }

    #[tokio::test]
    async fn test_group_not_found_returns_not_found_error() {
        let response = MockResponse {
            status: StatusCode::NOT_FOUND,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(result.unwrap_err(), ServiceError::GroupNotFound));
    }

    #[tokio::test]
    async fn test_group_gone_returns_gone_error() {
        let response = MockResponse {
            status: StatusCode::GONE,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(result.unwrap_err(), ServiceError::GroupGone));
    }

    #[tokio::test]
    async fn test_group_unauthorized_returns_unauthorized_error() {
        let response = MockResponse {
            status: StatusCode::UNAUTHORIZED,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(result.unwrap_err(), ServiceError::Unauthorized));
    }

    #[tokio::test]
    async fn test_group_rate_limited_returns_rate_limit_error() {
        let response = MockResponse {
            status: StatusCode::PAYLOAD_TOO_LARGE,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(
            result.unwrap_err(),
            ServiceError::RateLimitExceeded
        ));
    }

    #[tokio::test]
    async fn test_group_success_returns_ok() {
        let response = MockResponse {
            status: StatusCode::OK,
        };
        let result = service_error_for_group_status(response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_group_created_returns_ok() {
        let response = MockResponse {
            status: StatusCode::CREATED,
        };
        let result = service_error_for_group_status(response).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_group_unhandled_status_returns_unhandled_error() {
        let response = MockResponse {
            status: StatusCode::BAD_REQUEST,
        };
        let result = service_error_for_group_status(response).await;
        assert!(matches!(
            result.unwrap_err(),
            ServiceError::UnhandledResponseCode { http_code: 400 }
        ));
    }
}
