#[cfg(feature = "phonenumber")]
pub fn phonenumber_to_signal(
    number: &phonenumber::PhoneNumber,
) -> libsignal_core::E164 {
    number.to_string().parse().expect("valid phonenumber")
}

#[cfg(feature = "phonenumber")]
pub fn phonenumber_from_signal(
    number: &libsignal_core::E164,
) -> phonenumber::PhoneNumber {
    phonenumber::parse(None, number.to_string()).expect("valid phonenumber")
}

pub trait ToE164: Sized {
    fn to_e164(self) -> libsignal_core::E164;
}

impl ToE164 for libsignal_core::E164 {
    fn to_e164(self) -> libsignal_core::E164 {
        self
    }
}

#[cfg(feature = "phonenumber")]
impl ToE164 for phonenumber::PhoneNumber {
    fn to_e164(self) -> libsignal_core::E164 {
        phonenumber_to_signal(&self)
    }
}

#[cfg(feature = "phonenumber")]
impl ToE164 for &phonenumber::PhoneNumber {
    fn to_e164(self) -> libsignal_core::E164 {
        phonenumber_to_signal(self)
    }
}
