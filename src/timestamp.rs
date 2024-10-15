use std::{convert::TryInto, time::SystemTime};

pub(crate) trait TimestampExt {
    fn now() -> Self;
}

impl TimestampExt for libsignal_protocol::Timestamp {
    fn now() -> Self {
        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unix epoch in the past");
        Self::from_epoch_millis(
            unix_time.as_millis().try_into().expect("millis overflow"),
        )
    }
}
