use libsignal_protocol::SenderCertificate;

pub struct UnidentifiedAccess {
    pub key: Vec<u8>,
    pub certificate: SenderCertificate,
}
