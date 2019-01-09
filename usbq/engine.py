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

        # Mangle
        pm.hook.usbq_device_mangle(pkt=pkt)

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
        pm.hook.usbq_host_mangle(pkt=pkt)

        # # TODO: Handle REMOVE?
        # if pkt.type == 0:  # Data
        #     pm.hook.usbq_host_handle_data_pkt(pkt=pkt)
        # elif pkt.type == 1:  # ACK
        #     pm.hook.usbq_host_handle_ack_pkt(pkt=pkt)
        # elif pkt.type == 2:  # Management
        #     pm.hook.usbq_host_handle_management_pkt(pkt=pkt)

        # Encode
        send_data = pm.hook.usbq_host_encode(pkt=pkt)

        # Forward
        try:
            pm.hook.usbq_send_device_packet(data=send_data)
        except USBQDeviceNotConnected:
            log.info('USB device not connected yet. Dropping packet from host.')
            raise

    def run(self):
        try:
            log.info('Starting USB processing engine.')
            while True:
                # Emulate devices
                pm.hook.usbq_device_tick()

                # Used to prevent busy loop
                pm.hook.usbq_wait_for_packet()

                while pm.hook.usbq_device_has_packet():
                    self._do_device_packet()

                while pm.hook.usbq_host_has_packet():
                    self._do_host_packet()

        except KeyboardInterrupt:
            log.debug('Control-C: User requested exit.')
            pm.hook.usbq_teardown()
