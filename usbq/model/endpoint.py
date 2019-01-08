import attr

from ..dissect.usb import *
from ..dissect.defs import *
from ..usbmitm_proto import *

__all__ = ['Endpoint']


@attr.s(frozen=True)
class Endpoint:
    epnum = attr.ib(converter=int, default=0)
    eptype = attr.ib(converter=int, default=CTRL)
    epdir = attr.ib(converter=int, default=OUT)
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
