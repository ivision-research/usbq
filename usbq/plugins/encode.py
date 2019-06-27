import logging

import attr
from scapy.all import raw

from ..hookspec import hookimpl

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class USBEncode:
    'Encode host and device packets to USBQ packets.'

    @hookimpl
    def usbq_host_encode(self, pkt):
        return raw(pkt)

    @hookimpl
    def usbq_device_encode(self, pkt):
        return raw(pkt)
