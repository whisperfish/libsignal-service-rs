#![recursion_limit = "256"]
#![allow(clippy::uninlined_format_args)]

pub mod push_service;
pub mod websocket;

pub mod prelude {
    pub use crate::push_service::*;
}
