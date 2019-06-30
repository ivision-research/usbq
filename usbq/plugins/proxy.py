import logging
import select
import socket

import attr
from attr.converters import optional
from statemachine import State
from statemachine import StateMachine

from ..hookspec import hookimpl
from ..pm import pm
from ..usbmitm_proto import ManagementMessage
from ..usbmitm_proto import ManagementReload
from ..usbmitm_proto import ManagementReset
from ..usbmitm_proto import USBMessageDevice
from ..usbmitm_proto import USBMessageHost

log = logging.getLogger(__name__)
TIMEOUT = ([], [], [])


@attr.s(cmp=False)
class ProxyPlugin(StateMachine):
    'Proxy USB communications using a ubq_core enabled hardware device.'

    #: Address to listen to for USB device.
    _device_addr = attr.ib(converter=optional(str), default=None)

    #: Port to listen to for USB device.
    _device_port = attr.ib(converter=optional(int), default=None)

    #: Address to send to for USB host.
    _host_addr = attr.ib(converter=optional(str), default=None)

    #: Port to send to for USB host.
    _host_port = attr.ib(converter=optional(int), default=None)

    #: Timeout for select statement that waits for incoming USBQ packets
    timeout = attr.ib(converter=int, default=1)

    # States
    idle = State('idle', initial=True)
    running = State('running')

    # Valid state transitions
    start = idle.to(running)
    reset = running.to(idle) | idle.to(idle)
    reload = idle.to(running)

    EMPTY = []

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self._socks = []
        self._proxy_host = True
        self._proxy_device = True
        self._device_dst = None

        if self._device_addr is None or self._device_port is None:
            self._proxy_device = False

        if self._host_addr is None or self._host_port is None:
            self._proxy_host = False

        if self._proxy_device:
            log.info(f'Device listen to {self._device_addr}:{self._device_port}')
            self._device_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._device_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._device_sock.setblocking(False)
            self._device_sock.bind((self._device_addr, self._device_port))
            self._socks.append(self._device_sock)

        if self._proxy_host:
            log.info(f'Host send to {self._host_addr}:{self._host_port}')
            self._host_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._host_sock.setblocking(False)
            self._host_dst = (self._host_addr, self._host_port)
            self._socks.append(self._host_sock)

    def _has_data(self, socks, timeout=0):
        (read, write, error) = select.select(socks, self.EMPTY, socks, timeout)
        if len(read) != 0:
            return True
        return False

    @hookimpl
    def usbq_host_has_packet(self):
        if self._proxy_host:
            if self._has_data([self._host_sock]):
                return True

    @hookimpl
    def usbq_device_has_packet(self):
        if self._proxy_device:
            if self._has_data([self._device_sock]):
                return True

    @hookimpl
    def usbq_wait_for_packet(self):
        # Poll for data from non-proxy source
        queued_data = []
        if not self._proxy_host:
            queued_data += pm.hook.usbq_host_has_packet()
        if not self._proxy_device:
            queued_data += pm.hook.usbq_device_has_packet()

        if any(queued_data):
            return True
        else:
            # Wait
            if self._has_data(self._socks, timeout=self.timeout):
                return True

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
        return self._host_sock.sendto(data, self._host_dst) > 0

    @hookimpl
    def usbq_send_device_packet(self, data):
        if self._device_dst is not None:
            return self._device_sock.sendto(data, self._device_dst) > 0

    def on_start(self):
        log.info('Starting proxy.')

    def _send_host_mgmt(self, pkt):
        data = pm.hook.usbq_host_encode(
            pkt=USBMessageDevice(type=USBMessageHost.MitmType.MANAGEMENT, content=pkt)
        )
        self.usbq_send_host_packet(data)

    def _send_device_mgmt(self, pkt):
        data = pm.hook.usbq_device_encode(
            pkt=USBMessageHost(type=USBMessageDevice.MitmType.MANAGEMENT, content=pkt)
        )
        self.usbq_send_device_packet(data)

    def on_reset(self):
        log.info('Reset device.')

        self._send_device_mgmt(
            ManagementMessage(
                management_type=ManagementMessage.ManagementType.RESET,
                management_content=ManagementReset(),
            )
        )

    def on_reload(self):
        log.info('Reload device.')

        self._send_device_mgmt(
            ManagementMessage(
                management_type=ManagementMessage.ManagementType.RELOAD,
                management_content=ManagementReload(),
            )
        )
