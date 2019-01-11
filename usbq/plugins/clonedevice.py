import attr
import logging
import pickle

from pathlib import Path
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
class CloneDevice(StateMachine):
    'Observe and clone a device.'

    dest = attr.ib(converter=str, default='device.id')

    # States
    idle = State('idle', initial=True)
    observing = State('observing')

    # Valid state transitions
    newdevice = idle.to(observing)
    reset = observing.to(idle)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()

    def on_newdevice(self, newdev):
        log.info('New device detected.')
        self._desc = []

    def on_reset(self):
        log.info('Device reset.')
        ident = DeviceIdentity(self._desc)

        with Path(self.dest).open('wb') as f:
            pickle.dump(ident, f)
        log.debug(ident)
        log.info(f'Device definition pickled to {self.dest}.')

    @hookimpl
    def usbq_log_pkt(self, pkt):
        if not type(pkt) == USBMessageDevice:
            return

        if type(pkt.content) == ManagementMessage:
            if pkt.content.management_type == NEW_DEVICE:
                self.newdevice(pkt.content.management_content)
            elif pkt.content.management_type == RESET:
                self.reset()
        elif type(pkt.content) == USBMessageResponse:
            req = pkt.content.request
            res = pkt.content.response
            if type(req) == GetDescriptor:
                log.info(f'Added descriptor: {repr(res)}')
                self._desc.append(res)
