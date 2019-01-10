import attr
import logging
import time

from statemachine import StateMachine, State

from ..pm import pm
from ..hookspec import hookimpl
from ..usbmitm_proto import USBMessageDevice
from ..model import DeviceIdentity
from ..dissect.defs import *
from ..dissect.usb import *

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class USBHostScan(StateMachine):
    'Perform a scan of the host device for supported vendor and device ID values.'

    delay = attr.ib(default=15)

    # States
    idle = State('idle', initial=True)
    waiting = State('waiting')

    # Valid state transitions
    start = idle.to(waiting)
    timeout = waiting.to(idle)
    detected = waiting.to(idle)

    def __attrs_post_init__(self):
        # Workaround to mesh attr and StateMachine
        super().__init__()
        self._dev = None

    @property
    def dev(self):
        if self._dev is None:
            self._dev = pm.get_plugin('device')
        return self._dev

    @hookimpl
    def usbq_tick(self):
        # Start test
        if self.is_idle and self.dev.is_disconnected:
            self.start()
        elif self.is_waiting and (self.dev.is_connected or self.dev.is_configured):
            if (time.time() - self._start_time) > self.delay:
                self.timeout()

    @hookimpl
    def usbq_handle_device_request(self, content):
        'Look for requests to an endpoint other than 0 as evidence of the host supporting the device.'
        if content.ep.epnum == 0 and content.request.bRequest == 254:
            # MAX LUN request
            self.detected()
        elif self.dev.is_configured:
            self.detected()

    @hookimpl
    def usbq_device_identity(self):
        dd = {
            'bDescriptorType': 1,
            'bcdUSB': 512,
            'bDeviceClass': 0,
            'bDeviceSubClass': 0,
            'bDeviceProtocol': 0,
            'bMaxPacketSize': 64,
            'idVendor': 2352,
            'idProduct': 25925,
            'bcdDevice': 256,
            'iManufacturer': 0,
            'iProduct': 0,
            'iSerialNumber': 0,
            'bNumConfigurations': 1,
        }
        cd = {
            'bDescriptorType': 2,
            'bNumInterfaces': 1,
            'bConfigurationValue': 1,
            'iConfiguration': 0,
            'bmAttributes': 128,
            'bMaxPower': 100,
        }
        intd = {
            'bDescriptorType': 4,
            'bInterfaceNumber': 0,
            'bAlternateSetting': 0,
            'bNumEndpoint': 2,
            'bInterfaceClass': 8,
            'bInterfaceSubClass': 6,
            'bInterfaceProtocol': 80,
            'iInterface': 0,
        }
        endd_in = {
            'bDescriptorType': 5,
            'bEndpointAddress': bEndpointAddress(
                direction=IN, garbage=0, endpoint_number=1
            ),
            'bmAttributes': bmAttributes(
                garbage=0, behaviour=0, synchro=0, transfert=2
            ),
            'wMaxPacketSize': 512,
            'bInterval': 0,
        }
        endd_out = {
            'bDescriptorType': 5,
            'bEndpointAddress': bEndpointAddress(
                direction=OUT, garbage=0, endpoint_number=2
            ),
            'bmAttributes': bmAttributes(
                garbage=0, behaviour=0, synchro=0, transfert=2
            ),
            'wMaxPacketSize': 512,
            'bInterval': 0,
        }
        desc = {
            DEVICE_DESCRIPTOR: DeviceDescriptor(**dd),
            CONFIGURATION_DESCRIPTOR: [
                ConfigurationDescriptor(
                    descriptors=[
                        InterfaceDescriptor(**intd),
                        EndpointDescriptor(**endd_in),
                        EndpointDescriptor(**endd_out),
                    ],
                    **cd,
                )
            ],
            STRING_DESCRIPTOR: [
                # Supported languages
                StringDescriptor(),
                StringDescriptor(bString='USBIQUITOUS'.encode('utf-16le')),
                StringDescriptor(
                    bString='USBiquitous emulated generic device'.encode('utf-16le')
                ),
                StringDescriptor(bString='0xDEADBEEF'.encode('utf-16le')),
            ],
        }

        return DeviceIdentity(descriptors=desc)

    def on_start(self):
        log.info(f'Starting host USB scan.')
        # TODO: increment device identity
        self.dev.connect()
        self._start_time = time.time()

    def on_timeout(self):
        self.dev.disconnect()

    def on_detected(self):
        print('USB device support on host detected!')
        self.dev.disconnect()
