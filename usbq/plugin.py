'Default plugin implementations'

from .hookspec import hookimpl, USBQPluginDef


@hookimpl
def usbq_declare_plugins():
    # These are the bundled plugins.
    return {
        'proxy': USBQPluginDef(
            name='proxy',
            desc='Send and receive USB packets from a USBQ proxy device using the usbq_core module.',
            mod='usbq.plugins.proxy',
            clsname='ProxyPlugin',
        )
    }

