use libsignal_protocol::SenderCertificate;

pub struct UnidentifiedAccess {
    pub key: Vec<u8>,
    pub certificate: SenderCertificate,
}

/// Bitwise XOR of the 16-byte unidentified access keys for every recipient
/// of a multi-recipient sealed-sender message.
///
/// Mirrors the server's `CombinedUnidentifiedSenderAccessKeys`, which is base64-
/// encoded into the `Unidentified-Access-Key` header of
/// `PUT /v1/messages/multi_recipient`.
///
/// Construct with [`CombinedUnidentifiedSenderAccessKeys::from_access_keys`]
/// from the per-recipient [`UnidentifiedAccess::key`]s; round-trips losslessly
/// for an empty recipient set (yields the all-zero key).
#[derive(Clone, Copy)]
pub struct CombinedUnidentifiedSenderAccessKeys(pub [u8; 16]);

impl CombinedUnidentifiedSenderAccessKeys {
    /// XOR every `UnidentifiedAccess::key` (`UNIDENTIFIED_ACCESS_KEY_LENGTH`
    /// of 16 bytes each) into a single combined access key.
    pub fn from_access_keys<'a>(
        keys: impl IntoIterator<Item = &'a Vec<u8>>,
    ) -> Self {
        let mut combined = [0u8; 16];
        for key in keys {
            for (acc, b) in combined.iter_mut().zip(key.iter().take(16)) {
                *acc ^= *b;
            }
        }
        Self(combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_access_key_xors_recipients() {
        let a = vec![0u8; 16];
        let b = (0..16).collect::<Vec<u8>>();
        let c = vec![0xff; 16];

        let combined =
            CombinedUnidentifiedSenderAccessKeys::from_access_keys([
                &a, &b, &c,
            ]);
        // a XOR b XOR c == b XOR c (a is zero)
        let expected: [u8; 16] = std::array::from_fn(|i| b[i] ^ c[i]);
        assert_eq!(combined.0, expected);
    }

    #[test]
    fn combined_access_key_empty_is_zero() {
        let combined = CombinedUnidentifiedSenderAccessKeys::from_access_keys(
            std::iter::empty::<&Vec<u8>>(),
        );
        assert_eq!(combined.0, [0u8; 16]);
    }
}
