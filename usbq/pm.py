import importlib
import logging
import os.path
import sys
from collections import ChainMap
from collections import OrderedDict

import pluggy

from .exceptions import USBQInvocationError
from .hookspec import USBQ_EP
from .hookspec import USBQHookSpec
from .hookspec import USBQPluginDef

__all__ = ['AVAILABLE_PLUGINS', 'enable_plugins']

log = logging.getLogger(__name__)

# Search current directory. Needed for usbq_hooks.py
sys.path.insert(0, os.path.abspath('.'))

# Load the plugin manager and list available plugins
pm = pluggy.PluginManager(USBQ_EP)
pm.add_hookspecs(USBQHookSpec)
pm.load_setuptools_entrypoints(USBQ_EP)

AVAILABLE_PLUGINS = OrderedDict(ChainMap({}, *pm.hook.usbq_declare_plugins()))

# Add optional
HOOK_MOD = 'usbq_hooks'
HOOK_CLSNAME = 'USBQHooks'
AVAILABLE_PLUGINS['usbq_hooks'] = USBQPluginDef(
    name='usbq_hooks',
    desc='Optional user-provided hook implementations automatically loaded from from ./usbq_hooks.py',
    mod=HOOK_MOD,
    clsname=HOOK_CLSNAME,
    optional=True,
)


def enable_plugins(pm, pmlist=[], disabled=[], enabled=[]):
    extra = [(pdname, {}) for pdname in enabled]
    for pdinfo in pmlist + extra + [('usbq_hooks', {}), ('reload', {})]:
        pdname, pdopts = pdinfo

        if pdname not in AVAILABLE_PLUGINS:
            msg = f'{pdname} is not a valid USBQ plugin.'
            log.critical(msg)
            raise USBQInvocationError(msg)

        if pdname in disabled:
            log.info(f'Disabling plugin {pdname}.')
            continue

        pd = AVAILABLE_PLUGINS[pdname]

        try:
            mod = importlib.import_module(pd.mod)
            cls = getattr(mod, pd.clsname)

            try:
                pm.register(cls(**pdopts), name=pdname)
            except Exception as e:
                log.critical(
                    f'Could not start plugin {pdname} ({cls.__name__}) with options {pdopts}'
                )
                raise e

            log.debug(
                f'Loaded {pd.name} plugin from {pd.mod}:{pd.clsname} with kwargs {pdopts}'
            )
        except ModuleNotFoundError:
            if pd.optional:
                log.info(
                    f'Could not load optional plugin {pd.name}: Module not available.'
                )
            else:
                raise
        except AttributeError:
            if pd.optional:
                log.info(
                    f'Could not load optional plugin {pd.name}: Could not instantiate {pd.clsname}.'
                )
            else:
                raise
