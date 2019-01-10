import attr
import logging

from statemachine import StateMachine, State

from ..hookspec import hookimpl
from ..pm import pm
from ..usbmitm_proto import (
    USBMessageDevice,
    USBMessageHost,
    ManagementMessage,
    ManagementReset,
    ManagementNewDevice,
    USBMessageRequest,
    USBMessageResponse,
    NEW_DEVICE,
    RESET,
)
from ..model import DeviceIdentity
from ..dissect.defs import *
from ..dissect.usb import GetDescriptor, SetConfiguration

__all__ = ['USBDevice']

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class USBDevice(StateMachine):
    'Plugin for a stubbed out emulated USB device.'

    # States
    disconnected = State('disconnected', initial=True)
    connected = State('connected')
    configured = State('configured')
    terminated = State('terminated')

    # Valid state transitions
    connect = disconnected.to(connected)
    configure = connected.to(configured) | configured.to(configured)
    disconnect = connected.to(disconnected) | configured.to(disconnected)
    terminate = (
        connected.to(terminated)
        | configured.to(terminated)
        | disconnected.to(terminated)
    )

    _msgtypes = {ManagementMessage: 2, USBMessageResponse: 0}

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self._pkt_out = []
        self._pkt_in = []
        self._configuration = None
        self._identity = None

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
        assert type(data) == USBMessageHost
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
    def usbq_tick(self):
        while len(self._pkt_in) > 0:
            msg = self._pkt_in.pop(0)

            if type(msg.content) == USBMessageRequest:
                pm.hook.usbq_handle_device_request(dev=self, content=msg.content)
            else:
                raise NotImplementedError(f'Don\'t know how to handle {type(msg)} yet.')

    def _send_to_host(self, content):
        msgtype = self._msgtypes[type(content)]
        self._pkt_out.append(USBMessageDevice(type=msgtype, content=content))

    # Device ID
    @hookimpl
    def usbq_device_identity(self):
        # Return generic device ID
        return DeviceIdentity()

    # State handlers

    def on_connect(self):
        'Connect to the USB Host by queuing a new identity packet.'

        # Start the proxy
        proxy = pm.get_plugin('proxy')
        if not proxy.is_running:
            proxy.start()

        # fetch device identity of the emulated device
        log.info('Connecting emulated USB device.')
        self._ident = pm.hook.usbq_device_identity()
        self._send_to_host(
            ManagementMessage(
                management_type=NEW_DEVICE,
                management_content=self._ident.to_new_identity(),
            )
        )

    def on_disconnect(self):
        'Disconnect from the USB Host'

        log.info('Disconnecting emulated USB device.')
        self._send_to_host(
            ManagementMessage(
                management_type=RESET, management_content=ManagementReset()
            )
        )

    def on_configure(self):
        log.info(f'Device configuration set to {self._configuration}.')

    def on_terminate(self):
        self.on_disconnect()

    # Message handling

    @hookimpl
    def usbq_handle_device_request(self, content):
        'Process EP0 CONTROL requests for descriptors'

        ep = content.ep
        req = content.request

        # Handle EP0 CONTROL
        if not (
            ep.epnum == 0
            and ep.eptype == 0
            # and ep.epdir == 0
            and type(req) in [GetDescriptor, SetConfiguration]
        ):
            return

        # Descriptor request
        if req.bRequest == 6:
            desc = self._ident.from_request(req)
            if desc is not None:
                self._send_to_host(
                    USBMessageResponse(ep=ep, request=req, response=desc)
                )
                return True
        # Set Configuration
        elif req.bRequest == 9:
            self._configuration = req.bConfigurationValue
            self.configure()

    @hookimpl
    def usbq_teardown(self):
        self.terminate()
