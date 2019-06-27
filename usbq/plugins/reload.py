import importlib
import logging
from pathlib import Path

import attr

from ..hookspec import hookimpl
from ..pm import HOOK_CLSNAME, HOOK_MOD, pm

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

    @hookimpl
    def usbq_tick(self):
        if self.changed:
            # Reload
            try:
                mod = importlib.import_module(HOOK_MOD)
                importlib.reload(mod)
            except:
                log.critical('Could not reload usbq_hooks.py.')
                return

            # Unregister
            pm.unregister(name=HOOK_MOD)

            # Register
            cls = getattr(mod, HOOK_CLSNAME)
            pm.register(cls(), name=HOOK_MOD)
            log.info('Reloaded usbq_hooks.py.')
