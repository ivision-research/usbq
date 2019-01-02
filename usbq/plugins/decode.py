import attr
import logging

from ..hookspec import hookimpl
from ..usbmitm_proto import USBMessageHost, USBMessageDevice

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class USBDecode:
    'Decode raw USB packets into USBQ packets.'

    @hookimpl
    def usbq_host_decode(self, data):
        return USBMessageHost(data)

    @hookimpl
    def usbq_device_decode(self, data):
        return USBMessageDevice(data)
