//! Why a websocket failed. `reqwest_websocket::Error` displays as "tungstenite error" and
//! keeps the cause in `source()`; [`WebSocketError`] names the cause and what the socket
//! was doing.

use std::fmt;

pub use reqwest_websocket::HandshakeError;

/// What the websocket was doing when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketOperation {
    /// Upgrading the HTTP connection to a websocket.
    Connect,
    /// Reading the next frame from Signal.
    Receive,
    /// Sending a request of ours.
    SendRequest,
    /// Answering a request of Signal's.
    SendResponse,
    /// Sending a keep-alive.
    SendKeepAlive,
    /// Closing the socket.
    Close,
}

impl fmt::Display for WebSocketOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connecting",
            Self::Receive => "receiving a frame",
            Self::SendRequest => "sending a request",
            Self::SendResponse => "sending a response",
            Self::SendKeepAlive => "sending a keep-alive",
            Self::Close => "closing",
        })
    }
}

/// A websocket failure, by its cause.
#[derive(thiserror::Error, Debug)]
pub enum WebSocketError {
    /// Signal didn't complete the HTTP upgrade: it answered with an unexpected status, or
    /// without the headers an upgrade needs.
    #[error("websocket handshake failed: {0}")]
    Handshake(#[source] HandshakeError),

    /// The HTTP request carrying the upgrade didn't get an answer to shake hands over.
    #[error("websocket request failed: {0}")]
    Http(#[source] reqwest::Error),

    /// The websocket itself failed, in use: the connection was reset, a frame broke the
    /// protocol, or a TLS or I/O error cut it off.
    #[error("websocket failed while {operation}: {cause}")]
    Connection {
        operation: WebSocketOperation,
        #[source]
        cause: tungstenite::Error,
    },

    /// A failure `reqwest_websocket` reports that this crate doesn't know; displayed with
    /// its whole chain of causes.
    #[error("websocket failed while {operation}: {}", causes(.cause))]
    Other {
        operation: WebSocketOperation,
        #[source]
        cause: reqwest_websocket::Error,
    },
}

impl WebSocketError {
    /// Takes a `reqwest_websocket` error apart, noting what the socket was doing.
    pub(crate) fn new(
        operation: WebSocketOperation,
        error: reqwest_websocket::Error,
    ) -> Self {
        match error {
            reqwest_websocket::Error::Handshake(cause) => {
                Self::Handshake(cause)
            },
            reqwest_websocket::Error::Reqwest(cause) => Self::Http(cause),
            reqwest_websocket::Error::Tungstenite(cause) => {
                Self::Connection { operation, cause }
            },
            // Variants behind features this crate doesn't use, and ones a later
            // `reqwest_websocket` may add.
            cause => Self::Other { operation, cause },
        }
    }

    /// What the socket was doing when it failed.
    pub fn operation(&self) -> WebSocketOperation {
        match self {
            Self::Handshake(_) | Self::Http(_) => WebSocketOperation::Connect,
            Self::Connection { operation, .. }
            | Self::Other { operation, .. } => *operation,
        }
    }
}

/// An error and its sources, outermost first, joined with `: `.
fn causes(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reset_connection_names_itself() {
        let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let error = WebSocketError::new(
            WebSocketOperation::Receive,
            reqwest_websocket::Error::Tungstenite(tungstenite::Error::Io(
                reset,
            )),
        );
        assert!(matches!(
            error,
            WebSocketError::Connection {
                operation: WebSocketOperation::Receive,
                cause: tungstenite::Error::Io(_),
            }
        ));
        let text = error.to_string();
        assert!(
            text.starts_with(
                "websocket failed while receiving a frame: IO error: "
            ),
            "{text}"
        );
        assert!(!text.contains("tungstenite"), "{text}");
    }

    #[test]
    fn a_refused_upgrade_is_a_handshake_failure() {
        let error = WebSocketError::new(
            WebSocketOperation::Connect,
            reqwest_websocket::Error::Handshake(
                HandshakeError::UnexpectedStatusCode(
                    reqwest::StatusCode::FORBIDDEN,
                ),
            ),
        );
        assert_eq!(error.operation(), WebSocketOperation::Connect);
        assert_eq!(
            error.to_string(),
            "websocket handshake failed: unexpected status code: 403 Forbidden"
        );
    }

    #[test]
    fn an_unknown_error_shows_its_whole_chain() {
        let json = serde_json::from_str::<u8>("x").unwrap_err();
        let error = WebSocketError::new(
            WebSocketOperation::SendRequest,
            reqwest_websocket::Error::Json(json),
        );
        let text = error.to_string();
        assert!(
            text.starts_with("websocket failed while sending a request: serde_json error: expected value"),
            "{text}"
        );
    }
}

/// Why a request can't go over the websocket: its task has ended, or is about to. Why the
/// task ended is logged there and returned by [`SignalWebSocket::outcome`].
///
/// [`SignalWebSocket::outcome`]: super::SignalWebSocket::outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsClosingReason {
    /// Signal's side ended the stream without a close frame.
    StreamEnded,
    /// The application dropped the stream of Signal's requests, so a request from Signal has
    /// nobody to go to.
    RequestStreamDropped,
    /// The task had ended before a request could be handed to it.
    TaskEnded,
    /// The task ended while a request was waiting for its response.
    ResponsePending,
    /// The task had ended before a response to one of Signal's requests could be sent.
    ResponseUndeliverable,
    /// The task panicked.
    TaskPanicked,
}

impl fmt::Display for WsClosingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StreamEnded => {
                "Signal ended the stream without a close frame"
            },
            Self::RequestStreamDropped => {
                "the application dropped the stream of Signal's requests"
            },
            Self::TaskEnded => {
                "the socket's task had ended before the request was sent"
            },
            Self::ResponsePending => {
                "the socket's task ended while the response was awaited"
            },
            Self::ResponseUndeliverable => {
                "the socket's task had ended before the response could be sent"
            },
            Self::TaskPanicked => "the socket's task panicked",
        })
    }
}

/// A websocket frame that doesn't fit Signal's protocol.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum InvalidFrame {
    #[error("frame of unknown type")]
    UnknownType,
    #[error("frame typed as a request carries no request")]
    RequestWithoutRequest,
    #[error("frame typed as a response carries no response")]
    ResponseWithoutResponse,
    #[error("response to a keep-alive with the invalid HTTP status {0}")]
    InvalidKeepAliveStatus(u32),
    #[error("request carrying an envelope has no body")]
    EnvelopeWithoutBody,
}
