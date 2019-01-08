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

    # Transitions
    connect = disconnected.to(connected)
    disconnect = connected.to(disconnected)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self._queue = []

    @hookimpl
    def usbq_device_has_packet(self):
        return len(self._queue) > 0

    @hookimpl
    def usbq_device_decode(self, data):
        # Message is already decoded since it came from an emulated device
        assert type(data) == USBMessageDevice
        return data

    @hookimpl
    def usbq_get_device_packet(self):
        if len(self._queue) > 0:
            return self._queue.pop(0)

    @hookimpl
    def usbq_device_tick(self):
        if self.is_disconnected:
            self.connect()

    def _send(self, content):
        if type(content) in [ManagementMessage]:
            self._queue.append(USBMessageDevice(type=2, content=content))
        else:
            raise NotImplementedError(f'Add packet type: {type(content)}')

    def on_connect(self):
        'Connect to the USB Host by queuing a new identity packet.'

        # fetch device identity of the emulated device
        log.info('Connecting emulated USB device')
        ident = DeviceIdentity()
        self._send(
            ManagementMessage(
                management_type=NEW_DEVICE, management_content=ident.to_new_identity()
            )
        )

    def on_disconnect(self):
        'Disconnect from the USB Host'

        log.info('Disconnecting emulated USB device')
        self._queue.append(ManagementReset())
