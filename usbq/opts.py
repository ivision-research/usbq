import logging
import pickle

import click

# Shared options

__all__ = [
    'network_options',
    'pcap_options',
    'identity_options',
    'add_options',
    'standard_plugin_options',
    'load_ident',
]

log = logging.getLogger(__name__)

network_options = [
    click.option(
        '--proxy-addr',
        default='127.0.0.1',
        type=str,
        help='IP address of the USB MITM proxy hardware.',
        envvar='USBQ_PROXY_ADDR',
    ),
    click.option(
        '--proxy-port',
        default=64241,
        type=int,
        help='Port number of the USB MITM proxy hardware.',
        envvar='USBQ_PROXY_PORT',
    ),
    click.option(
        '--listen-addr',
        default='0.0.0.0',
        type=str,
        help='IP address to bind to for incoming packets from the USB MITM proxy hardware.',
        envvar='USBQ_LISTEN_ADDR',
    ),
    click.option(
        '--listen-port',
        default=64240,
        type=int,
        help='Port to bind to for incoming packets from the USB MITM proxy hardware.',
        envvar='USBQ_LISTEN_PORT',
    ),
]

pcap_options = [
    click.option(
        '--pcap',
        default='usb.pcap',
        type=click.Path(dir_okay=False, writable=True, exists=False),
        help='PCAP file to record USB traffic.',
    )
]

identity_options = [
    click.option(
        '--device-identity',
        default=None,
        type=click.File('rb'),
        help='File to load pickled instance of a USB device.',
    )
]


def load_ident(fn):
    if fn is not None:
        d = pickle.load(fn)
        log.debug(f'Loaded device ID: {d}')
        return d
    else:
        return None


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


def standard_plugin_options(
    proxy_addr, proxy_port, listen_addr, listen_port, pcap, dump=False, **kwargs
):
    res = [
        (
            'proxy',
            {
                'device_addr': listen_addr,
                'device_port': listen_port,
                'host_addr': proxy_addr,
                'host_port': proxy_port,
            },
        ),
        ('pcap', {'pcap': pcap}),
        ('decode', {}),
        ('encode', {}),
    ]

    if dump:
        res.append(('hexdump', {}))

    return res
