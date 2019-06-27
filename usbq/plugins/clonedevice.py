import logging
import pickle
from pathlib import Path

import attr
from statemachine import State, StateMachine

from ..dissect.usb import GetDescriptor
from ..hookspec import hookimpl
from ..model import DeviceIdentity
from ..usbmitm_proto import (
    NEW_DEVICE,
    RESET,
    ManagementMessage,
    USBMessageDevice,
    USBMessageResponse,
)

__all__ = ['CloneDevice']

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
    reset = observing.to(idle) | idle.to(idle)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()

    def on_newdevice(self, newdev):
        log.info('New device detected.')
        self._desc = []

    def on_reset(self):
        # Persist captured DeviceIdentity
        if not hasattr(self, '_desc'):
            return

        if len(self._desc) > 0:
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
                log.info('Device reset.')
                self.reset()
        elif type(pkt.content) == USBMessageResponse:
            req = pkt.content.request
            res = pkt.content.response
            if type(req) == GetDescriptor:
                log.info(f'Added descriptor: {repr(res)}')
                self._desc.append(res)

    @hookimpl
    def usbq_teardown(self):
        self.reset()
