import attr
import logging

from .exceptions import USBQDeviceNotConnected

__all__ = ['USBQEngine']

log = logging.getLogger(__name__)


@attr.s
class USBQEngine:
    'Packet forwarding engine for device to host MITM.'

    #: Plugin manager instance.
    pm = attr.ib()

    def _do_device_packet(self):
        data = self.pm.hook.usbq_get_device_packet()
        if data is not None:
            self.pm.hook.usbq_send_host_packet(data=data)

    def _do_host_packet(self):
        data = self.pm.hook.usbq_get_host_packet()
        if data is not None:
            try:
                self.pm.hook.usbq_send_device_packet(data=data)
            except USBQDeviceNotConnected:
                log.info('USB device not connected yet. Dropping packet from host.')
                pass

    def run(self):
        try:
            log.info('Starting USB processing engine.')
            while True:
                # Used to prevent busy loop
                self.pm.hook.usbq_wait_for_packet()

                if self.pm.hook.usbq_has_device_packet()[0]:
                    self._do_device_packet()

                if self.pm.hook.usbq_has_host_packet()[0]:
                    self._do_host_packet()

        except KeyboardInterrupt:
            log.debug('Normal exit from Control-C.')
            pass
