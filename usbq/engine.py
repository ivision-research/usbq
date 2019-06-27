import logging

import attr

from .exceptions import USBQDeviceNotConnected
from .pm import pm

__all__ = ['USBQEngine']

log = logging.getLogger(__name__)


@attr.s
class USBQEngine:
    'Packet forwarding engine for device to host MITM.'

    def _do_device_packet(self):
        data = pm.hook.usbq_get_device_packet()

        # Decode and log
        pkt = pm.hook.usbq_device_decode(data=data)
        pm.hook.usbq_log_pkt(pkt=pkt)

        # Mangle
        pm.hook.usbq_device_modify(pkt=pkt)

        # Encode
        send_data = pm.hook.usbq_device_encode(pkt=pkt)

        # Forward
        pm.hook.usbq_send_host_packet(data=send_data)

    def _do_host_packet(self):
        data = pm.hook.usbq_get_host_packet()

        # Decode and log
        pkt = pm.hook.usbq_host_decode(data=data)
        pm.hook.usbq_log_pkt(pkt=pkt)

        # Mangle
        pm.hook.usbq_host_modify(pkt=pkt)

        # Encode
        send_data = pm.hook.usbq_host_encode(pkt=pkt)

        # Forward
        try:
            pm.hook.usbq_send_device_packet(data=send_data)
        except USBQDeviceNotConnected:
            log.info('USB device not connected yet. Dropping packet from host.')
            raise

    def event(self):
        # Let plugins do work
        if hasattr(pm.hook, 'usbq_tick'):
            pm.hook.usbq_tick()

        # Used to prevent busy loop
        pm.hook.usbq_wait_for_packet()

        while any(pm.hook.usbq_device_has_packet()):
            self._do_device_packet()

        while any(pm.hook.usbq_host_has_packet()):
            self._do_host_packet()

    def run(self):
        ipy = pm.get_plugin('ipython')
        if ipy is not None:
            log.info('Starting USB processing engine with IPython UI.')
            ipy.run(engine=self)
        else:
            log.info('Starting USB processing engine.')
            while True:
                try:
                    self.event()
                except KeyboardInterrupt:
                    break

        log.critical('User requested exit.')
        pm.hook.usbq_teardown()

        # Take one more pass through the loop to send/recv packets
        self.event()
        return
