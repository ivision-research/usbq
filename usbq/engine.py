import attr
import logging

from .exceptions import USBQDeviceNotConnected
from .pm import pm

__all__ = ['USBQEngine']

log = logging.getLogger(__name__)
EMPTY = []


@attr.s
class USBQEngine:
    'Packet forwarding engine for device to host MITM.'

    def _do_device_packet(self):
        data = pm.hook.usbq_get_device_packet()

        # Decode and log
        pkt = pm.hook.usbq_device_decode(data=data)
        pm.hook.usbq_log_pkt(pkt=pkt)

        # Encode
        send_data = pm.hook.usbq_device_encode(pkt=pkt)

        # Forward
        pm.hook.usbq_send_host_packet(data=send_data)

    def _do_host_packet(self):
        data = pm.hook.usbq_get_host_packet()

        # Decode and log
        pkt = pm.hook.usbq_host_decode(data=data)
        pm.hook.usbq_log_pkt(pkt=pkt)

        # Encode
        send_data = pm.hook.usbq_host_encode(pkt=pkt)

        # Forward
        try:
            pm.hook.usbq_send_device_packet(data=data)
        except USBQDeviceNotConnected:
            log.info('USB device not connected yet. Dropping packet from host.')

    def run(self):
        try:
            log.info('Starting USB processing engine.')
            while True:
                # Used to prevent busy loop
                pm.hook.usbq_wait_for_packet()

                if pm.hook.usbq_device_has_packet():
                    self._do_device_packet()

                if pm.hook.usbq_host_has_packet():
                    self._do_host_packet()

        except KeyboardInterrupt:
            log.debug('Control-C: User requested exit.')
