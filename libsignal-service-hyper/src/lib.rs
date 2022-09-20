#![recursion_limit = "256"]

#[cfg(feature = "unsend-futures")]
compile_error!("`libsignal-service-hyper` cannot be compiled with the feature `unsend-futures` from `libsignal-service`.");

pub mod push_service;
pub mod websocket;

pub mod prelude {
    pub use crate::push_service::*;
}
