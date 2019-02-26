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
        ),
        'pcap': USBQPluginDef(
            name='pcap',
            desc='Write a PCAP file containing USB communications.',
            mod='usbq.plugins.pcap',
            clsname='PcapFileWriter',
        ),
        'decode': USBQPluginDef(
            name='decode',
            desc='Decode raw USBQ driver packets to Scapy representation.',
            mod='usbq.plugins.decode',
            clsname='USBDecode',
        ),
        'encode': USBQPluginDef(
            name='encode',
            desc='Encode raw USBQ driver packets to Scapy representation.',
            mod='usbq.plugins.encode',
            clsname='USBEncode',
        ),
        'hostscan': USBQPluginDef(
            name='hostscan',
            desc='Scan host for supported devices.',
            mod='usbq.plugins.hostscan',
            clsname='USBHostScan',
        ),
        'device': USBQPluginDef(
            name='device',
            desc='Emulate a USB device.',
            mod='usbq.plugins.device',
            clsname='USBDevice',
        ),
        'hexdump': USBQPluginDef(
            name='hexdump',
            desc='Display USBQ packet and hexdump of USB payload.',
            mod='usbq.plugins.hexdump',
            clsname='Hexdump',
        ),
        'hostfuzz': USBQPluginDef(
            name='hostfuzz',
            desc='Fuzz device packets headed to the host.',
            mod='usbq.plugins.hostfuzz',
            clsname='Hostfuzz',
        ),
        'clonedevice': USBQPluginDef(
            name='clonedevice',
            desc='Observe device behavior to clone device configuration and descriptors.',
            mod='usbq.plugins.clonedevice',
            clsname='CloneDevice',
        ),
        'reload': USBQPluginDef(
            name='reload',
            desc='Monitor usbq_hooks.py file and reload if changed.',
            mod='usbq.plugins.reload',
            clsname='ReloadUSBQHooks',
        ),
    }

