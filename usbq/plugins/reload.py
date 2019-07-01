import importlib
import inspect
import logging
import traceback
from pathlib import Path

import attr

from ..hookspec import hookimpl
from ..pm import HOOK_CLSNAME
from ..pm import HOOK_MOD
from ..pm import pm

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class ReloadUSBQHooks:
    'Reload usbq_hooks.py when it changes'

    _hookfile = attr.ib(default='usbq_hooks.py')

    def __attrs_post_init__(self):
        self._mtime = None
        self._path = Path(self._hookfile)
        if self._path.is_file():
            log.info(f'Monitoring {self._path} for changes.')
            self._mtime = self.mtime

    @property
    def mtime(self):
        if self._path.is_file():
            return self._path.stat().st_mtime

    @property
    def changed(self):
        if self._mtime != self.mtime:
            self._mtime = self.mtime
            log.debug(f'Monitored hook file {self._path} was modified.')
            return True
        else:
            return False

    def _catch(self, outcome):
        try:
            outcome.get_result()
        except Exception:
            frm = inspect.trace()[-1]
            mod = inspect.getmodule(frm[0])
            if mod.__name__ == HOOK_MOD:
                log.critical(f'Error executing hook in {HOOK_MOD}. Disabling plugin.')
                traceback.print_tb(outcome.excinfo[2])
                pm.unregister(name=HOOK_MOD)
                outcome.force_result(None)

    @hookimpl(hookwrapper=True)
    def usbq_tick(self):
        if self.changed:
            # Reload
            try:
                mod = importlib.import_module(HOOK_MOD)
                importlib.reload(mod)
            except Exception:
                log.critical('Could not reload usbq_hooks.py.')
                yield
                return

            # Unregister
            pm.unregister(name=HOOK_MOD)

            # Register
            cls = getattr(mod, HOOK_CLSNAME)
            pm.register(cls(), name=HOOK_MOD)
            log.info('Reloaded usbq_hooks.py.')

        outcome = yield
        self._catch(outcome)

    def _wrapper(self, *args, **kwargs):
        outcome = yield
        self._catch(outcome)


# Create usbq_hook error handlers for all defined hooks
for hookname in [
    'usbq_wait_for_packet',
    'usbq_log_pkt',
    'usbq_device_has_packet',
    'usbq_get_device_packet',
    'usbq_device_decode',
    'usbq_device_modify',
    'usbq_device_encode',
    'usbq_host_has_packet',
    'usbq_get_host_packet',
    'usbq_host_decode',
    'usbq_host_encode',
    'usbq_host_modify',
    'usbq_send_device_packet',
    'usbq_send_host_packet',
    'usbq_device_identity',
    'usbq_handle_device_request',
    'usbq_ipython_ns',
    'usbq_connected',
    'usbq_disconnected',
    'usbq_teardown',
]:
    setattr(
        ReloadUSBQHooks, hookname, hookimpl(ReloadUSBQHooks._wrapper, hookwrapper=True)
    )
