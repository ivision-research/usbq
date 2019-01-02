import pluggy
import importlib
import logging

from collections import ChainMap
from frozendict import frozendict

from .hookspec import USBQ_EP, USBQHookSpec

__all__ = ['AVAILABLE_PLUGINS', 'enable_plugins']

log = logging.getLogger(__name__)

# Load the plugin manager and list available plugins
pm = pluggy.PluginManager(USBQ_EP)
pm.add_hookspecs(USBQHookSpec)
pm.load_setuptools_entrypoints(USBQ_EP)
AVAILABLE_PLUGINS = frozendict(ChainMap({}, *pm.hook.usbq_declare_plugins()))


def enable_plugins(pm, pmlist):
    for pdinfo in pmlist:
        pdname, pdopts = pdinfo

        if pdname not in AVAILABLE_PLUGINS:
            raise ValueError(f'{pdname} is not a valid USBQ plugin.')

        pd = AVAILABLE_PLUGINS[pdname]

        log.debug(f'Loading {pd.name} plugin from {pd.mod}:{pd.clsname}')
        mod = importlib.import_module(pd.mod)
        cls = getattr(mod, pd.clsname)

        pm.register(cls(**pdopts))
