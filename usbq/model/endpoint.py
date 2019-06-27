import attr

from ..defs import USBDefs
from ..dissect.usb import EndpointDescriptor, bEndpointAddress, bmAttributes

__all__ = ['Endpoint']


@attr.s(frozen=True)
class Endpoint:
    epnum = attr.ib(converter=int, default=0)
    eptype = attr.ib(converter=int, default=USBDefs.EP.TransferType.CTRL)
    epdir = attr.ib(converter=int, default=USBDefs.EP.Direction.OUT)
    maxpkt = attr.ib(converter=int, default=64)
    interval = attr.ib(converter=int, default=0)

    @property
    def descriptor(self):
        addr = bEndpointAddress(direction=self.epdir, endpoint_number=self.epnum)
        attr = bmAttributes(transfert=self.eptype)
        return EndpointDescriptor(
            bEndpointAddress=addr,
            bmAttributes=attr,
            wMaxPacketSize=self.maxpkt,
            bInterval=self.interval,
        )
