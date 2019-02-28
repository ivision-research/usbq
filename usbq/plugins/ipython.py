import attr
import logging
import IPython

from ..pm import pm, HOOK_MOD, HOOK_CLSNAME
from ..hookspec import hookimpl

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class IPythonUI:
    'IPython UI for usbq'

    @hookimpl
    def usbq_ipython_ns(self):
        res = {'pm': pm}
        return res

    def run(self, engine):
        self._engine = engine
        # Short enough to be responsive but not so short as to ramp up CPU usage
        proxy = pm.get_plugin('proxy')
        proxy.timeout = 0.01

        ns = {key: value for d in pm.hook.usbq_ipython_ns() for key, value in d.items()}

        IPython.terminal.pt_inputhooks.register('usbq', self._ipython_loop)
        IPython.start_ipython(argv=['-i', '-c', '%gui usbq'], user_ns=ns)

    def _ipython_loop(self, context):
        while not context.input_is_ready():
            self._engine.event()

    def _load_ipy_ns(self):
        res = {'pm': pm}
        res.update({name: plugin for name, plugin in pm.list_name_plugin()})
        return res

