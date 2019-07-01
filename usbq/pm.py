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

__all__ = ['AVAILABLE_PLUGINS', 'enable_plugins', 'enable_tracing']

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
    for pdinfo in [('reload', {})] + pmlist + extra + [('usbq_hooks', {})]:
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
        except Exception as e:
            if pd.mod == 'usbq_hooks':
                log.critical(f'Could not load usbq_hooks.py: {e}')
            else:
                raise


def enable_tracing():
    # Trace pluggy
    tracer = logging.getLogger('trace')
    before_msg = None

    def before(hook_name, hook_impls, kwargs):
        nonlocal before_msg

        arglst = [
            f'{key}={repr(value)}'
            for key, value in sorted(kwargs.items(), key=lambda v: v[0])
        ]
        argstr = ', '.join(arglst)
        plst = ', '.join([p.plugin_name for p in reversed(hook_impls)])
        before_msg = f'{hook_name}({argstr}) [{plst}]'

    def after(outcome, hook_name, hook_impls, kwargs):
        nonlocal before_msg

        res = outcome.get_result()
        has_result = [
            type(res) == list and len(res) > 0,
            type(res) != list and res is not None,
            hook_name
            in [
                'usbq_device_modify',
                'usbq_host_modify',
                'usbq_connected',
                'usbq_disconnected',
                'usbq_teardown',
            ],
        ]
        if any(has_result):
            tracer.debug(f'{before_msg} -> {repr(res)} [{type(res)}]')

    pm.add_hookcall_monitoring(before, after)
