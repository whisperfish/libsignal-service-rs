type ParseError = <libsignal_core::E164 as std::str::FromStr>::Err;

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

pub trait TryIntoE164: Sized {
    fn try_into_e164(self) -> Result<libsignal_core::E164, ParseError>;
}

impl TryIntoE164 for &str {
    fn try_into_e164(self) -> Result<libsignal_core::E164, ParseError> {
        self.parse()
    }
}

impl TryIntoE164 for libsignal_core::E164 {
    fn try_into_e164(self) -> Result<libsignal_core::E164, ParseError> {
        Ok(self)
    }
}

#[cfg(feature = "phonenumber")]
impl TryIntoE164 for phonenumber::PhoneNumber {
    fn try_into_e164(self) -> Result<libsignal_core::E164, ParseError> {
        Ok(phonenumber_to_signal(&self))
    }
}

#[cfg(feature = "phonenumber")]
impl TryIntoE164 for &phonenumber::PhoneNumber {
    fn try_into_e164(self) -> Result<libsignal_core::E164, ParseError> {
        Ok(phonenumber_to_signal(self))
    }
}
