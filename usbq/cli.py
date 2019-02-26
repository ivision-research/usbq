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
from .opts import *

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


def _setup_logging(logfile, debug):
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Turn on logging
    root = logging.getLogger()
    root.setLevel(level)

    # Colors and formats
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    fh = logging.FileHandler(logfile, 'w')
    fh.setLevel(level)
    formatter = ColoredFormatter(fmt=FORMAT, field_styles=LOG_FIELD_STYLES)
    ch.setFormatter(formatter)
    fh.setFormatter(logging.Formatter(FORMAT))
    root.addHandler(ch)
    root.addHandler(fh)


def _enable_tracing():
    # Trace pluggy
    tracer = logging.getLogger('trace')

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
    ctx.obj['dump'] = ctx.params['dump']
    ctx.obj['enable_plugin'] = ctx.params['enable_plugin']
    ctx.obj['disable_plugin'] = ctx.params['disable_plugin']

    if ctx.invoked_subcommand is None:
        click.echo(f'usbq version {__version__}\n')
        click.echo(ctx.get_help())
        click.echo('\nAvailable plugins:\n')
        for pd in sorted(AVAILABLE_PLUGINS.values(), key=lambda pd: pd.name):
            click.echo(f'- {pd.name}: {pd.desc}')
    else:
        _setup_logging(logfile, debug)

        if trace:
            _enable_tracing()

    return 0


#
# Commands
#


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
def mitm(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    'Man-in-the-Middle USB device to host communications.'

    enable_plugins(
        pm,
        standard_plugin_options(
            proxy_addr, proxy_port, listen_addr, listen_port, pcap, dump=ctx.obj['dump']
        ),
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
    proxy = pm.get_plugin('proxy')
    proxy.start()
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
def hostscan(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap):
    'Scan USB host for supported devices.'

    enable_plugins(
        pm,
        standard_plugin_options(
            proxy_addr, proxy_port, None, None, pcap, dump=ctx.obj['dump']
        )
        + [('device', {}), ('hostscan', {})],
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
@add_options(identity_options)
def hostfuzz(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, device_identity
):
    'Proxy USB device and mutate packets to fuzz the host.'

    ident = load_ident(device_identity)
    enable_plugins(
        pm,
        standard_plugin_options(
            proxy_addr, proxy_port, None, None, pcap, dump=ctx.obj['dump']
        )
        + [('device', {'ident': ident}), ('hostfuzz', {})],
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
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
            proxy_addr, proxy_port, listen_addr, listen_port, pcap, dump=ctx.obj['dump']
        )
        + [('clonedevice', {'dest': device_identity})],
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
    clone = pm.get_plugin('clonedevice')
    proxy = pm.get_plugin('proxy')
    proxy.start()
    USBQEngine().run()


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
@add_options(identity_options)
def device(
    ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, device_identity
):
    'Emulate a USB device.'

    ident = load_ident(device_identity)

    if ident is not None:
        kwargs = {'ident': ident}
    else:
        kwargs = {}

    enable_plugins(
        pm,
        standard_plugin_options(
            proxy_addr, proxy_port, None, None, pcap, dump=ctx.obj['dump']
        )
        + [('device', kwargs)],
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
    device = pm.get_plugin('device')
    device.connect()
    USBQEngine().run()


if __name__ == "__main__":
    sys.exit(main(auto_envvar_prefix='USBQ'))  # pragma: no cover
