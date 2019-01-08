import attr

from ..dissect.usb import *
from .endpoint import Endpoint


@attr.s
class Interface:
    _descriptors = attr.ib(default=[])
    cls = attr.ib(converter=int, default=0)
    subcls = attr.ib(converter=int, default=0)
    proto = attr.ib(converter=int, default=0)

    @property
    def descriptors(self):
        desc = [
            InterfaceDescriptor(
                bInterfaceClass=self.cls,
                bInterfaceSubClass=self.subcls,
                bInterfaceProtocol=self.proto,
            )
        ]
        nbep = 0
        for d in self._descriptors:
            if type(d) is Endpoint:
                desc.append(d.descriptor)
                nbep += 1
            else:
                desc.append(d)
        desc[0].bNumEndpoint = nbep
        return desc
