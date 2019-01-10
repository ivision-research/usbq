# -*- coding: utf-8 -*-

import sys
import click
import logging

from coloredlogs import ColoredFormatter

from . import __version__
from .pm import pm, AVAILABLE_PLUGINS, enable_plugins
from .engine import USBQEngine


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
@click.option('--trace', is_flag=True, default=False, help='Trace plugins.')
@click.pass_context
def main(ctx, debug, trace):
    '''USBiquitous: USB Intrustion Toolkit'''

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
            formatter = ColoredFormatter(fmt=FORMAT, field_styles=LOG_FIELD_STYLES)
            ch.setFormatter(formatter)
            root.addHandler(ch)

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
    click.option(
        '--disable-plugin', type=str, multiple=True, default=[], help='Disable plugin'
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


def add_options(options):
    def _add_options(func):
        for option in reversed(options):
            func = option(func)
        return func

    return _add_options


def standard_plugin_options(proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    return [
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


#
# Commands
#


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
def mitm(ctx, disable_plugin, proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    'Man-in-the-Middle USB device to host communications.'

    enable_plugins(
        pm,
        standard_plugin_options(proxy_addr, proxy_port, listen_addr, listen_port, pcap),
        disabled=disable_plugin,
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
def hostscan(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, disable_plugin
):
    'Scan USB host for supported devices.'

    enable_plugins(
        pm,
        standard_plugin_options(proxy_addr, proxy_port, None, None, pcap)
        + [('device', {}), ('hostscan', {})],
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(_network_options)
@add_options(_pcap_options)
def device(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, disable_plugin):
    'Emulate a USB device.'

    enable_plugins(
        pm,
        standard_plugin_options(proxy_addr, proxy_port, None, None, pcap)
        + [('device', {})],
        disabled=disable_plugin,
    )
    device = pm.hook.usbq_get_device()
    device.connect()
    USBQEngine().run()


if __name__ == "__main__":
    sys.exit(main(auto_envvar_prefix='USBQ'))  # pragma: no cover
