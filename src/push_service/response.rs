use std::future::Future;

use reqwest::StatusCode;

use crate::{
    proto::WebSocketResponseMessage,
    websocket::registration::RegistrationSessionMetadataResponse,
};

use super::ServiceError;

pub(crate) async fn json_or_unhandled<R, T>(
    response: R,
) -> Result<T, ServiceError>
where
    T: for<'de> serde::Deserialize<'de>,
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    let status = response.status_code();
    let body = response.text().await?;
    serde_json::from_str(&body).map_err(move |error| {
        tracing::error!(%error, "JSON decoding in error handling failed; returning UnhandledResponseCode");
        ServiceError::UnhandledResponseCode { status, body }
    })
}

fn parse_retry_after(header: &str) -> Option<chrono::Duration> {
    let val = header.parse::<i64>().inspect_err(
        |error| tracing::warn!(%error, "could not parse rate limit duration"),
    ).ok()?;

    Some(chrono::Duration::seconds(val))
}

/// Baseline HTTP→[`ServiceError`] mapping for responses that do not need
/// endpoint-specific decoding.
async fn baseline_decode<R>(response: R) -> Result<R, ServiceError>
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
        StatusCode::NOT_FOUND => Err(ServiceError::NotFoundError),
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::TOO_MANY_REQUESTS => {
            Err(ServiceError::RateLimitExceeded {
                retry_after: response
                    .header("retry-after")
                    .and_then(parse_retry_after),
            })
        },
        StatusCode::LOCKED => {
            let locked = json_or_unhandled(response).await?;
            Err(ServiceError::Locked(locked))
        },
        // Signal uses non-standard 499 (deprecated client version) and 508
        // (request rejected); no StatusCode constants exist for these.
        code if code.as_u16() == 499 => Err(ServiceError::DeprecatedVersion),
        code if code.as_u16() == 508 => Err(ServiceError::ServerRejected),
        code => {
            let body = response.text().await?;
            tracing::debug!(status_code = %code, %body, "unhandled HTTP response");
            Err(ServiceError::UnhandledResponseCode { status: code, body })
        },
    }
}

/// Endpoint-specific HTTP error decoder.
pub(crate) trait ResponseErrors {
    fn decode_error<R>(
        response: R,
    ) -> impl Future<Output = Result<R, ServiceError>> + Send
    where
        R: SignalServiceResponse + Send,
        ServiceError: From<<R as SignalServiceResponse>::Error>;
}

/// Generate a [`ResponseErrors`] impl from status → variant arms:
/// - `CODE => Variant(Type)` — decode JSON body via [`json_or_unhandled`].
/// - `CODE => Variant` — unit variant, body discarded.
/// - `CODE => fn helper` — call helper.
///
/// `CODE` is a `reqwest::StatusCode` constant name, or a raw status code
/// like `440` when no dedicated constant exists.
///
/// Unlisted statuses return `Ok(response)` and fall through to
/// [`baseline_decode`].
macro_rules! error_mapper {
    // tt-muncher: accumulate `pattern => body` arms, then emit one match.
    (@munch $response:ident; [$($out:tt)*] ;) => {
        match $response.status_code() {
            $($out)*
            _ => Ok($response),
        }
    };
    // Named `StatusCode` constants become path patterns…
    (@munch $response:ident; [$($out:tt)*] ; $status:ident => $($rest:tt)*) => {
        error_mapper!(@action $response; [$($out)*] ;
            [reqwest::StatusCode::$status] $($rest)*)
    };
    // …raw codes that have no dedicated `StatusCode` constant (`440 => …`)
    // become guards.
    (@munch $response:ident; [$($out:tt)*] ; $status:literal => $($rest:tt)*) => {
        error_mapper!(@action $response; [$($out)*] ;
            [code if code.as_u16() == $status] $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] fn $helper:path, $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($helper($response).await),] ;
            $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] $variant:ident ( $ty:ty ), $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($crate::push_service::ServiceError::$variant(
                $crate::push_service::response::json_or_unhandled::<R, $ty>($response).await?,
            )),] ;
            $($rest)*)
    };
    (@action $response:ident; [$($out:tt)*] ; [$($pat:tt)*] $variant:ident, $($rest:tt)*) => {
        error_mapper!(@munch $response;
            [$($out)* $($pat)* => Err($crate::push_service::ServiceError::$variant),] ;
            $($rest)*)
    };
    (
        $( #[$m:meta] )*
        $name:ident: $($arms:tt)*
    ) => {
        $( #[$m] )*
        #[derive(Debug, Clone, Copy)]
        pub(crate) struct $name;

        impl $crate::push_service::response::ResponseErrors for $name {
            fn decode_error<R>(
                response: R,
            ) -> impl std::future::Future<Output = Result<R, $crate::push_service::ServiceError>> + Send
            where
                R: $crate::push_service::response::SignalServiceResponse + Send,
                $crate::push_service::ServiceError: From<<R as $crate::push_service::response::SignalServiceResponse>::Error>,
            {
                async move { error_mapper!(@munch response; [] ; $($arms)*) }
            }
        }
    };
}

pub(crate) use error_mapper;

// Signal-Server: generic/baseline decoder, no endpoint-specific errors
error_mapper! {
    /// Baseline-only decoder.
    Baseline:
}

pub(crate) async fn device_limit_reached<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    #[derive(Debug, serde::Deserialize)]
    struct LinkedDeviceNumberError {
        current: u32,
        max: u32,
    }
    match json_or_unhandled::<R, LinkedDeviceNumberError>(response).await {
        Ok(error) => ServiceError::DeviceLimitReached {
            current: error.current,
            max: error.max,
        },
        Err(error) => error,
    }
}

pub(crate) async fn session_rate_limited<R>(response: R) -> ServiceError
where
    R: SignalServiceResponse,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    let retry_after =
        response.header("retry-after").and_then(parse_retry_after);
    match json_or_unhandled::<R, RegistrationSessionMetadataResponse>(response)
        .await
    {
        Ok(session) => ServiceError::VerificationSessionRateLimited {
            session,
            retry_after,
        },
        Err(error) => error,
    }
}

pub(crate) async fn service_error_for_status<R, E>(
    response: R,
) -> Result<R, ServiceError>
where
    R: SignalServiceResponse + Send,
    E: ResponseErrors,
    ServiceError: From<<R as SignalServiceResponse>::Error>,
{
    let response = E::decode_error(response).await?;
    baseline_decode(response).await
}

#[async_trait::async_trait]
pub(crate) trait SignalServiceResponse {
    type Error: std::error::Error;

    fn status_code(&self) -> StatusCode;

    async fn json<U>(self) -> Result<U, Self::Error>
    where
        for<'de> U: serde::Deserialize<'de>;

    async fn text(self) -> Result<String, Self::Error>;
    fn header(&self, name: &str) -> Option<&str>;

    /// Baseline error handling only (specialised codes fall through to
    /// [`UnhandledResponseCode`][ServiceError::UnhandledResponseCode]).
    fn service_error_for_status(
        self,
    ) -> impl Future<Output = Result<Self, ServiceError>> + Send
    where
        Self: Sized + Send,
        ServiceError: From<<Self as SignalServiceResponse>::Error>,
    {
        service_error_for_status::<Self, Baseline>(self)
    }

    /// Error handling specialised for the endpoint named by `E`; every code
    /// `E` does not own falls through to the baseline.
    fn service_error_for_status_as<E>(
        self,
    ) -> impl Future<Output = Result<Self, ServiceError>> + Send
    where
        Self: Sized + Send,
        E: ResponseErrors,
        ServiceError: From<<Self as SignalServiceResponse>::Error>,
    {
        service_error_for_status::<Self, E>(self)
    }
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

    fn header(&self, name: &str) -> Option<&str> {
        self.headers().get(name).and_then(|v| {
            v.to_str()
                .inspect_err(|e| {
                    tracing::warn!(?e, "could not read header as string")
                })
                .ok()
        })
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

    fn header(&self, name: &str) -> Option<&str> {
        let (_header, value) = self
            .headers
            .iter()
            .filter_map(|hdr| hdr.split_once(":"))
            .find(|(header, _body)| header.trim().eq_ignore_ascii_case(name))?;
        Some(value.trim())
    }
}
