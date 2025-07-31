use libsignal_core::InvalidDeviceId;
use libsignal_protocol::{Aci, DeviceId, Pni, ProtocolAddress, ServiceId};

pub trait ServiceIdExt {
    fn to_protocol_address(
        self,
        device_id: DeviceId,
    ) -> Result<ProtocolAddress, InvalidDeviceId>;

    fn aci(self) -> Option<Aci>;

    fn pni(self) -> Option<Pni>;
}

impl<A> ServiceIdExt for A
where
    A: Into<ServiceId>,
{
    fn to_protocol_address(
        self,
        device_id: DeviceId,
    ) -> Result<ProtocolAddress, InvalidDeviceId> {
        let service_id: ServiceId = self.into();
        Ok(ProtocolAddress::new(
            service_id.service_id_string(),
            device_id,
        ))
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
