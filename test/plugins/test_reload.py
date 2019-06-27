import pytest

from importlib import import_module
from pathlib import Path

from usbq.plugins.reload import ReloadUSBQHooks
from usbq.pm import pm, enable_plugins

VER_ONE = '''
from usbq.hookspec import hookimpl

class USBQHooks():
    @hookimpl
    def usbq_host_has_packet(self):
        return False
'''

VER_TWO = '''
from usbq.hookspec import hookimpl

class USBQHooks():
    @hookimpl
    def usbq_host_has_packet(self):
        return True
'''


@pytest.fixture
def hookfile():
    res = Path('usbq_hooks.py')
    yield res
    res.unlink()


def test_reload(hookfile):
    hookfile.write_text(VER_ONE)
    enable_plugins(pm)
    reloader = ReloadUSBQHooks()

    assert not reloader.changed
    assert not all(pm.hook.usbq_host_has_packet())

    hookfile.write_text(VER_TWO)
    reloader.usbq_tick()
    assert all(pm.hook.usbq_host_has_packet())
