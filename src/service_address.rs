use libsignal_protocol::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};

pub trait ServiceIdExt {
    fn to_protocol_address(
        self,
        device_id: impl Into<DeviceId>,
    ) -> ProtocolAddress;

    fn aci(self) -> Option<Aci>;

    fn pni(self) -> Option<Pni>;
}

impl<A> ServiceIdExt for A
where
    A: Into<ServiceId>,
{
    fn to_protocol_address(
        self,
        device_id: impl Into<DeviceId>,
    ) -> ProtocolAddress {
        let service_id: ServiceId = self.into();
        ProtocolAddress::new(service_id.service_id_string(), device_id.into())
    }

    fn aci(self) -> Option<Aci> {
        match self.into() {
            ServiceId::Aci(aci) => Some(aci),
            ServiceId::Pni(_) => None,
        }
    }

    fn pni(self) -> Option<Pni> {
        match self.into() {
            ServiceId::Aci(_) => None,
            ServiceId::Pni(pni) => Some(pni),
        }
    }
}
