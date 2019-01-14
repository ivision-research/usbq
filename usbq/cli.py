# -*- coding: utf-8 -*-

import sys
import click
import logging
import pickle

from coloredlogs import ColoredFormatter

from . import __version__
from .pm import pm, AVAILABLE_PLUGINS, enable_plugins
from .engine import USBQEngine
from .exceptions import USBQException

__all__ = []
log = logging.getLogger(__name__)

FORMAT = '%(levelname)8s [%(name)24s]: %(message)s'
LOG_FIELD_STYLES = {
    'asctime': {'color': 'green'},
    'hostname': {'color': 'magenta'},
    'levelname': {'color': 'green', 'bold': True},
    'name': {'color': 'blue'},
    'programname': {'color': 'cyan'},
}


@click.group(invoke_without_command=True)
@click.option('--debug', is_flag=True, default=False, help='Enable usbq debug logging.')
@click.option(
    '--logfile',
    type=click.Path(writable=True, dir_okay=False),
    default='debug.log',
    help='Logfile for --debug output',
)
@click.option('--trace', is_flag=True, default=False, help='Trace plugins.')
@click.option(
    '--dump', is_flag=True, default=False, help='Dump USBQ packets to console.'
)
@click.option(
    '--disable-plugin', type=str, multiple=True, default=[], help='Disable plugin'
)
@click.option(
    '--enable-plugin', type=str, multiple=True, default=[], help='Enable plugin'
)
@click.pass_context
def main(ctx, debug, trace, logfile, **kwargs):
    '''USBiquitous: USB Intrustion Toolkit'''

    ctx.ensure_object(dict)
    ctx.obj['params'] = ctx.params

    if ctx.invoked_subcommand is None:
        click.echo(f'usbq version {__version__}\n')
        click.echo(ctx.get_help())
        click.echo('\nAvailable plugins:\n')
        for pd in sorted(AVAILABLE_PLUGINS.values(), key=lambda pd: pd.name):
            click.echo(f'- {pd.name}: {pd.desc}')
    else:
        if debug:
            # Turn on logging
            root = logging.getLogger()
            root.setLevel(logging.DEBUG)

            # Colors and formats
            ch = logging.StreamHandler(sys.stdout)
            ch.setLevel(logging.DEBUG)
            fh = logging.FileHandler(logfile, 'w')
            fh.setLevel(logging.DEBUG)
            formatter = ColoredFormatter(fmt=FORMAT, field_styles=LOG_FIELD_STYLES)
            ch.setFormatter(formatter)
            fh.setFormatter(logging.Formatter(FORMAT))
            root.addHandler(ch)
            root.addHandler(fh)

        if trace:
            # Trace pluggy
            tracer = logging.getLogger('trace')

            # def dotrace(msg):
            #     tracer.debug(msg.strip('\n'))

            # pm.trace.root.setwriter(dotrace)
            # pm.enable_tracing()

            def before(hook_name, hook_impls, kwargs):
                arglst = [
                    f'{key}={repr(value)}'
                    for key, value in sorted(kwargs.items(), key=lambda v: v[0])
                ]
                argstr = ', '.join(arglst)
                plst = ', '.join([p.plugin_name for p in reversed(hook_impls)])
                tracer.debug(f'{hook_name}({argstr}) [{plst}]')

            def after(outcome, hook_name, hook_impls, kwargs):
                res = outcome.get_result()
                tracer.debug(f'{hook_name} -> {repr(res)} [{type(res)}]')

            pm.add_hookcall_monitoring(before, after)

    return 0


# Shared options

_network_options = [
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

_pcap_options = [
    click.option(
        '--pcap',
        default='usb.pcap',
        type=click.Path(dir_okay=False, writable=True, exists=False),
        help='PCAP file to record USB traffic.',
    )
]

_identity_options = [
    click.option(
        '--device-identity',
        default=None,
        type=click.File('rb'),
        help='File to load pickled instance of a USB device.',
    )
]


def _load_ident(fn):
    if fn is not None:
        return pickle.load(fn)
    else:
        return None


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


def standard_plugin_options(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap
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

    if ctx.obj['params']['dump']:
        res.append(('hexdump', {}))

    return res


#
# Commands
#


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
def mitm(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    'Man-in-the-Middle USB device to host communications.'

    enable_plugins(
        pm,
        standard_plugin_options(
            ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap
        ),
        disabled=ctx.obj['params']['disable_plugin'],
        enabled=ctx.obj['params']['enable_plugin'],
    )
    proxy = pm.get_plugin('proxy')
    proxy.start()
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
def hostscan(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    'Scan USB host for supported devices.'

    enable_plugins(
        pm,
        standard_plugin_options(ctx, proxy_addr, proxy_port, None, None, pcap)
        + [('device', {}), ('hostscan', {})],
        disabled=ctx.obj['params']['disable_plugin'],
        enabled=ctx.obj['params']['enable_plugin'],
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
@add_options(_identity_options)
def hostfuzz(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, device_identity
):
    'Proxy USB device and mutate packets to fuzz the host.'

    ident = _load_ident(device_identity)
    enable_plugins(
        pm,
        standard_plugin_options(ctx, proxy_addr, proxy_port, None, None, pcap)
        + [('device', {'ident': ident}), ('hostfuzz', {})],
        disabled=ctx.obj['params']['disable_plugin'],
        enabled=ctx.obj['params']['enable_plugin'],
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
@click.option(
    '--device-identity',
    default='device.id',
    type=click.Path(writable=True, dir_okay=False),
    help='File to save pickled instance of a USB device.',
)
def clonedevice(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, device_identity
):
    'Create a USB device model from proxied communications.'

    enable_plugins(
        pm,
        standard_plugin_options(
            ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap
        )
        + [('clonedevice', {'dest': device_identity})],
        disabled=ctx.obj['params']['disable_plugin'],
        enabled=ctx.obj['params']['enable_plugin'],
    )
    clone = pm.get_plugin('clonedevice')
    proxy = pm.get_plugin('proxy')
    proxy.start()
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
@add_options(_identity_options)
def device(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, device_identity
):
    'Emulate a USB device.'

    ident = _load_ident(device_identity)
    enable_plugins(
        pm,
        standard_plugin_options(ctx, proxy_addr, proxy_port, None, None, pcap)
        + [('device', {'ident': ident})],
        disabled=ctx.obj['params']['disable_plugin'],
        enabled=ctx.obj['params']['enable_plugin'],
    )
    device = pm.get_plugin('device')
    device.connect()
    USBQEngine().run()


if __name__ == "__main__":
    sys.exit(main(auto_envvar_prefix='USBQ'))  # pragma: no cover
