import attr
import logging

from ..hookspec import hookimpl
from ..usbmitm_proto import USBMessageDevice

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class USBHostScan:
    'Perform a scan of the host device for supported vendor and device ID values.'

    # @hookimpl
    # def usbq_device_has_packet(self):
    #     return self._has_data([self._device_sock])

    # @hookimpl
    # def usbq_wait_for_packet(self):
    #     socks = [self._host_sock, self._device_sock]
    #     return self._has_data(socks, timeout=1)

    # @hookimpl
    # def usbq_get_device_packet(self):
    #     data, self._device_dst = self._device_sock.recvfrom(4096)
    #     return data
