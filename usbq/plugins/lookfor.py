import logging

import attr
import usb
from statemachine import State
from statemachine import StateMachine

from ..hookspec import hookimpl

log = logging.getLogger(__name__)


@attr.s
class USBId:
    vendor = attr.ib(converter=int)
    product = attr.ib(converter=int)

    def __str__(self):
        return f'{self.vendor:04x}:{self.product:04x}'

    @staticmethod
    def parse(usb_id):
        if usb_id is None:
            return

        raw_vid, raw_pid = usb_id.split(':')
        return USBId(vendor=int(raw_vid, 16), product=int(raw_pid, 16))


@attr.s(cmp=False)
class LookForDevice(StateMachine):
    usb_id = attr.ib(converter=USBId.parse, default=None)

    # States
    idle = State('idle', initial=True)
    present = State('present')
    not_present = State('not_present')

    # Valid state transitions
    connected = idle.to(present) | not_present.to(present)
    disconnected = idle.to(not_present) | present.to(not_present)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()

        if self.usb_id is not None:
            log.info(f'Searching for USB device {self.usb_id}')

    def _look(self):
        dev = usb.core.find(idVendor=self.usb_id.vendor, idProduct=self.usb_id.product)
        if dev is not None and not self.is_present:
            self.connected()
        elif dev is None and self.is_present:
            self.disconnected()

    def on_connected(self):
        log.info(f'USB device {self.usb_id} connected')

    def on_disconnected(self):
        log.info(f'USB device {self.usb_id} disconnected')

    @hookimpl
    def usbq_tick(self):
        if self.usb_id is not None:
            self._look()
