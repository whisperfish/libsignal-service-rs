use libsignal_protocol::SenderCertificate;

#[derive(Clone)]
pub struct UnidentifiedAccess {
    pub key: Vec<u8>,
    pub certificate: SenderCertificate,
}
