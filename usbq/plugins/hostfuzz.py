import attr
import logging
import time

from statemachine import StateMachine, State

from ..pm import pm
from ..hookspec import hookimpl
from ..usbmitm_proto import USBMessageDevice
from ..model import DeviceIdentity
from ..dissect.defs import *
from ..dissect.usb import *

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class Hostfuzz(StateMachine):
    'Fuzz device packets heading to the host.'

    delay = attr.ib(default=15)

    # States
    idle = State('idle', initial=True)
    waiting = State('waiting')

    # Valid state transitions
    start = idle.to(waiting)
    timeout = waiting.to(idle)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self.proxy = pm.get_plugin('proxy')

    @hookimpl
    def usbq_tick(self):
        if self.is_idle:
            self.start()

    def on_start(self):
        log.info(f'Starting host fuzzing test.')

        if self.proxy.is_idle:
            self.proxy.start()

        self._start_time = time.time()

    def on_timeout(self):
        if self.proxy.is_running:
            self.proxy.reset()
            self.proxy.reload()
