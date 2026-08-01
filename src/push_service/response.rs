use std::future::Future;

use reqwest::StatusCode;

use crate::{
    proto::WebSocketResponseMessage,
    websocket::registration::RegistrationSessionMetadataResponse,
};

use super::{
    AccountMismatchedDevices, AccountStaleDevices, MismatchedDevices,
    ProofRequired, ServiceError, StaleDevices, VerificationDeliveryFailure,
};

async fn json_or_unhandled<R, T>(response: R) -> Result<T, ServiceError>
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
/// Unlisted statuses return `Ok(response)` and fall through to
/// [`baseline_decode`].
macro_rules! error_mapper {
    // tt-muncher accumulating decoded arms, then emitting a whole match.
    (@build $response:ident; $($arms:tt)*) => {
        error_mapper!(@emit $response; [] ; $($arms)*)
    };
    (@emit $response:ident; [$($out:tt)*] ;) => {
        match $response.status_code() {
            $($out)*
            _ => Ok($response),
        }
    };
    (@emit $response:ident; [$($out:tt)*] ; $status:ident => fn $helper:path, $($rest:tt)*) => {
        error_mapper!(@emit $response;
            [$($out)* StatusCode::$status => Err($helper($response).await),] ;
            $($rest)*)
    };
    (@emit $response:ident; [$($out:tt)*] ; $status:ident => $variant:ident ( $ty:ty ), $($rest:tt)*) => {
        error_mapper!(@emit $response;
            [$($out)* StatusCode::$status => Err(ServiceError::$variant(
                json_or_unhandled::<R, $ty>($response).await?,
            )),] ;
            $($rest)*)
    };
    (@emit $response:ident; [$($out:tt)*] ; $status:ident => $variant:ident, $($rest:tt)*) => {
        error_mapper!(@emit $response;
            [$($out)* StatusCode::$status => Err(ServiceError::$variant),] ;
            $($rest)*)
    };
    (
        $( #[$m:meta] )*
        $name:ident: $($arms:tt)*
    ) => {
        $( #[$m] )*
        #[derive(Debug, Clone, Copy)]
        pub(crate) struct $name;

        impl ResponseErrors for $name {
            fn decode_error<R>(
                response: R,
            ) -> impl Future<Output = Result<R, ServiceError>> + Send
            where
                R: SignalServiceResponse + Send,
                ServiceError: From<<R as SignalServiceResponse>::Error>,
            {
                async move { error_mapper!(@build response; $($arms)*) }
            }
        }
    };
}

error_mapper! {
    /// Baseline-only decoder.
    Baseline:
}

error_mapper! {
    PutMessages:
        CONFLICT => MismatchedDevicesException(MismatchedDevices),
        GONE => StaleDevices(StaleDevices),
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        NOT_FOUND => UnregisteredRecipient,
        PRECONDITION_REQUIRED => ProofRequiredError(ProofRequired),
}

error_mapper! {
    #[allow(dead_code)]
    PutMultiRecipientMessages:
        CONFLICT => MultiRecipientMismatchedDevices(Vec<AccountMismatchedDevices>),
        GONE => MultiRecipientStaleDevices(Vec<AccountStaleDevices>),
        PAYLOAD_TOO_LARGE => MessageTooLarge,
        PRECONDITION_REQUIRED => ProofRequiredError(ProofRequired),
}

error_mapper! {
    LinkDevice:
        FORBIDDEN => InvalidDeviceVerificationCode,
        CONFLICT => DeviceCapabilityDowngrade,
        LENGTH_REQUIRED => fn device_limit_reached,
}

error_mapper! {
    GetProvisioningCode:
        LENGTH_REQUIRED => fn device_limit_reached,
}

error_mapper! {
    CreateVerificationSession:
        TOO_MANY_REQUESTS => fn session_rate_limited,
}

error_mapper! {
    PatchVerificationSession:
        FORBIDDEN => TokenNotAccepted(RegistrationSessionMetadataResponse),
        NOT_FOUND => NoSuchSession,
        UNPROCESSABLE_ENTITY => InvalidVerificationSessionId,
        TOO_MANY_REQUESTS => fn session_rate_limited,
}

error_mapper! {
    RequestVerificationCode:
        NOT_FOUND => NoSuchSession,
        CONFLICT => RegistrationSessionConflict(RegistrationSessionMetadataResponse),
        IM_A_TEAPOT => InvalidTransportMode(RegistrationSessionMetadataResponse),
        UNPROCESSABLE_ENTITY => InvalidVerificationSessionId,
        TOO_MANY_REQUESTS => fn session_rate_limited,
        UNAVAILABLE_FOR_LEGAL_REASONS => VerificationDeliveryFailed(VerificationDeliveryFailure),
}

error_mapper! {
    SubmitVerificationCode:
        NOT_FOUND => NoSuchSession,
        CONFLICT => RegistrationSessionConflict(RegistrationSessionMetadataResponse),
        UNPROCESSABLE_ENTITY => InvalidVerificationSessionId,
        TOO_MANY_REQUESTS => fn session_rate_limited,
}

error_mapper! {
    PostRegistration:
        CONFLICT => DeviceTransferAvailable,
}

error_mapper! {
    PutUsernameLink:
        CONFLICT => UsernameHashNotSet,
}

error_mapper! {
    GetAttachmentUploadForm:
        PAYLOAD_TOO_LARGE => AttachmentTooLarge,
}

error_mapper! {
    SubmitChallenge:
        PRECONDITION_REQUIRED => ChallengeNotAccepted,
}

async fn device_limit_reached<R>(response: R) -> ServiceError
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

async fn session_rate_limited<R>(response: R) -> ServiceError
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

pub(crate) trait ReqwestExt
where
    Self: Sized,
{
    /// Baseline error handling only (specialised codes fall through to
    /// [`UnhandledResponseCode`][ServiceError::UnhandledResponseCode]).
    fn service_error_for_status(
        self,
    ) -> impl Future<Output = Result<reqwest::Response, ServiceError>> + Send;

    /// Error handling specialised for the endpoint named by `E`; every code
    /// `E` does not own falls through to the baseline.
    fn service_error_for_status_as<E>(
        self,
    ) -> impl Future<Output = Result<reqwest::Response, ServiceError>> + Send
    where
        E: ResponseErrors;
}

impl ReqwestExt for reqwest::Response {
    fn service_error_for_status(
        self,
    ) -> impl Future<Output = Result<reqwest::Response, ServiceError>> + Send
    {
        service_error_for_status::<reqwest::Response, Baseline>(self)
    }

    fn service_error_for_status_as<E>(
        self,
    ) -> impl Future<Output = Result<reqwest::Response, ServiceError>> + Send
    where
        E: ResponseErrors,
    {
        service_error_for_status::<reqwest::Response, E>(self)
    }
}
