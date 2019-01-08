import attr
import logging

from scapy.all import raw
from statemachine import StateMachine, State

from ..hookspec import hookimpl
from ..pm import pm
from ..usbmitm_proto import (
    USBMessageDevice,
    USBMessageHost,
    ManagementMessage,
    ManagementReset,
    ManagementNewDevice,
    NEW_DEVICE,
    RESET,
)
from ..model import DeviceIdentity

__all__ = ['USBDevice']

log = logging.getLogger(__name__)

dehex = lambda v: int(v, base=16)


@attr.s(cmp=False)
class USBDevice(StateMachine):
    'Plugin for a stubbed out emulated USB device.'

    #: USB device class, hex
    dclass = attr.ib(converter=dehex)

    #: USB device class
    dsubclass = attr.ib(converter=dehex)

    #: USB device class
    dproto = attr.ib(converter=dehex)

    # States
    disconnected = State('disconnected', initial=True)
    connected = State('connected')

    # Valid state transitions
    connect = disconnected.to(connected)
    disconnect = connected.to(disconnected)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self._pkt_out = []
        self._pkt_in = []

    # Proxy hooks

    @hookimpl
    def usbq_device_has_packet(self):
        return len(self._pkt_out) > 0

    @hookimpl
    def usbq_get_device_packet(self):
        if len(self._pkt_out) > 0:
            return self._pkt_out.pop(0)

    @hookimpl
    def usbq_send_device_packet(self, data):
        self._pkt_in.append(data)
        return True

    # Decode/Encode is not required

    @hookimpl
    def usbq_device_decode(self, data):
        # Message is already decoded since it came from an emulated device
        assert type(data) == USBMessageDevice
        return data

    @hookimpl
    def usbq_host_encode(self, pkt):
        # Message does not need to be encoded since it is going to an emulated device
        assert type(pkt) == USBMessageHost
        return pkt

    @hookimpl
    def usbq_device_tick(self):
        if self.is_disconnected:
            self.connect()

    def _send_to_host(self, content):
        if type(content) in [ManagementMessage]:
            self._pkt_out.append(USBMessageDevice(type=2, content=content))
        else:
            raise NotImplementedError(f'Add packet type: {type(content)}')

    # State handlers

    def on_connect(self):
        'Connect to the USB Host by queuing a new identity packet.'

        # fetch device identity of the emulated device
        log.info('Connecting emulated USB device')
        ident = DeviceIdentity()
        self._send_to_host(
            ManagementMessage(
                management_type=NEW_DEVICE, management_content=ident.to_new_identity()
            )
        )

    def on_disconnect(self):
        'Disconnect from the USB Host'

        log.info('Disconnecting emulated USB device')
        self._send_to_host(
            ManagementMessage(
                management_type=RESET, management_content=ManagementReset()
            )
        )
