# -*- coding: utf-8 -*-
import logging
import sys

import click
import click_config_file
from coloredlogs import ColoredFormatter

from . import __version__
from .engine import USBQEngine
from .opts import add_options
from .opts import identity_options
from .opts import load_ident
from .opts import network_options
from .opts import pcap_options
from .opts import standard_plugin_options
from .opts import usb_device_options
from .pm import AVAILABLE_PLUGINS
from .pm import enable_plugins
from .pm import enable_tracing
from .pm import pm

__all__ = []
log = logging.getLogger(__name__)

CMD_NAME = 'usbq'
CONFIG_FILE = CMD_NAME + '.cfg'
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
@click_config_file.configuration_option(cmd_name='usbq', config_file_name='usbq.cfg')
def main(ctx, debug, trace, logfile, **kwargs):
    '''USBQ: Python programming framework for monitoring and modifying USB communications.'''

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
        click.echo(
            f'\nDefault config file: {click.get_app_dir(CMD_NAME)}/{CONFIG_FILE}'
        )
    else:
        _setup_logging(logfile, debug)

        if trace:
            enable_tracing()

    return 0


#
# Commands
#


@main.command()
@click.pass_context
@add_options(network_options)
@add_options(pcap_options)
@add_options(usb_device_options)
def mitm(ctx, proxy_addr, proxy_port, listen_addr, listen_port, pcap, usb_id):
    'Man-in-the-Middle USB device to host communications.'

    enable_plugins(
        pm,
        standard_plugin_options(
            proxy_addr, proxy_port, listen_addr, listen_port, pcap, dump=ctx.obj['dump']
        )
        + [('lookfor', {'usb_id': usb_id})],
        disabled=ctx.obj['disable_plugin'],
        enabled=ctx.obj['enable_plugin'],
    )
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
    sys.exit(main())  # pragma: no cover
