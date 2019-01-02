import attr
import logging
import socket
import select

from frozendict import frozendict
from ..hookspec import hookimpl
from ..exceptions import USBQDeviceNotConnected

log = logging.getLogger(__name__)
TIMEOUT = ([], [], [])


@attr.s(cmp=False)
class ProxyPlugin:
    'Proxy USB communications using a ubq_core enabled hardware device.'

    #: Address to listen to for USB device.
    device_addr = attr.ib(converter=str)

    #: Port to listen to for USB device.
    device_port = attr.ib(converter=int)

    #: Address to send to for USB host.
    host_addr = attr.ib(converter=str)

    #: Port to send to for USB host.
    host_port = attr.ib(converter=int)

    EMPTY = []

    def __attrs_post_init__(self):
        log.info(f'Device listen to {self.device_addr}:{self.device_port}')
        self._device_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._device_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._device_sock.setblocking(False)
        self._device_sock.bind((self.device_addr, self.device_port))
        self._device_dst = None

        log.info(f'Host send to {self.host_addr}:{self.host_port}')
        self._host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._host_sock.setblocking(False)
        self._host_dst = (self.host_addr, self.host_port)

    def _has_data(self, socks, timeout=0):
        (read, write, error) = select.select(socks, self.EMPTY, socks, timeout)
        if len(read) != 0:
            return True
        return False

    @hookimpl
    def usbq_host_has_packet(self):
        return self._has_data([self._host_sock])

    @hookimpl
    def usbq_device_has_packet(self):
        return self._has_data([self._device_sock])

    @hookimpl
    def usbq_wait_for_packet(self):
        socks = [self._host_sock, self._device_sock]
        return self._has_data(socks, timeout=1)

    @hookimpl
    def usbq_get_host_packet(self):
        data, self._host_dst = self._host_sock.recvfrom(4096)
        return data

    @hookimpl
    def usbq_get_device_packet(self):
        data, self._device_dst = self._device_sock.recvfrom(4096)
        return data

    @hookimpl
    def usbq_send_host_packet(self, data):
        return self._host_sock.sendto(data, self._host_dst)

    @hookimpl
    def usbq_send_device_packet(self, data):
        if self._device_dst is None:
            raise USBQDeviceNotConnected()

        return self._device_sock.sendto(data, self._device_dst)
