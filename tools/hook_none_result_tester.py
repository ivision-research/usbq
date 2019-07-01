'''
Test tool for checking plugin caller's resistance to None results.

1. Copy to usbq_hooks.py.
2. Test each hook by doing whatever calls that hook. Usually a device unplug/plug will work.
3. Increment to the next hook.
4. Go to #2

'''
import logging

from usbq.hookspec import hookimpl

log = logging.getLogger(__name__)

HOOKS = [
    'usbq_tick',
    'usbq_wait_for_packet',
    'usbq_log_pkt',
    'usbq_device_has_packet',
    'usbq_get_device_packet',
    'usbq_device_decode',
    'usbq_device_modify',
    'usbq_device_encode',
    'usbq_host_has_packet',
    'usbq_get_host_packet',
    'usbq_host_decode',
    'usbq_host_encode',
    'usbq_host_modify',
    'usbq_send_device_packet',
    'usbq_send_host_packet',
    'usbq_device_identity',
    'usbq_handle_device_request',
    'usbq_ipython_ns',
    'usbq_connected',
    'usbq_disconnected',
    'usbq_teardown',
]


class USBQHooks:
    def _boom(self):
        raise Exception()


hookname = HOOKS[0]
log.critical(f'Testing {hookname}')
setattr(USBQHooks, hookname, hookimpl(USBQHooks._boom))
