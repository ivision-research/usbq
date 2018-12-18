#!/usr/bin/env python

import time

from .hid import HIDDevice
from usbmitm.dissect.hid import ReportDescriptor
from usbmitm.dissect.usbmitm_proto import USBEp, USBMessageResponse
from usbmitm.lib.interface import Interface
from usbmitm.lib.endpoint import Endpoint
from usbmitm.lib.identity import DeviceIdentity

from usbmitm.dissect.usb import *
from usbmitm.dissect.hid import *

from .azerty import *

KeyboardInterface = Interface(
    descriptors=[Endpoint(1, INT, IN, 8, 24), HIDDescriptor()],
    cls=HID,
    subcls=1,
    proto=1,
)


class Keyboard(HIDDevice):
    RELEASE = "\x00\x00\x00\x00\x00\x00\x00\x00"

    def __init__(self, args):
        ident = DeviceIdentity.from_interface(KeyboardInterface, speed=LOW_SPEED)
        ident.set_strings(
            [
                "\x09\x04",
                "USBiquitous emulated keyboard".encode('utf-16le'),
                "USBIQUITOUS".encode('utf-16le'),
            ]
        )
        super(Keyboard, self).__init__(args, ident, ReportDescriptor())
        self.ep1 = USBEp(epnum=1, eptype=INT, epdir=0)

    def send_event(self, event):
        self.send_in_data(USBMessageResponse(ep=self.ep1, data=event))

    def keypress(self, key):
        """ Press key """
        self.send_event(key)

    def release_key(self):
        """ Release key actually press """
        self.send_event(Keyboard.RELEASE)

    def key(self, key):
        """ Press and release key """
        self.keypress(key)
        time.sleep(0.2)
        self.release_key()
        time.sleep(0.2)


class RubberDucky(Keyboard):
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--input", "-i", metavar="FILE", help="File to run")
        parser.add_argument("--raw-input", "-r", metavar="FILE", help="Raw File to run")

    def __init__(self, args):
        super(RubberDucky, self).__init__(args)
        self.load = lambda: []
        if args.input:
            self.input = args.input
            self.load = self.text_load
        if args.raw_input:
            self.input = args.raw_input
            self.load = self.raw_load

    def raw_load(self):
        r = []
        with open(self.input, "r") as f:
            last = 0
            for l in reversed(f.readlines()):
                t, e = l.split(" ", 1)
                e = e[:-1]
                if last == 0:
                    r.insert(0, (e, 0))
                else:
                    r.insert(0, (e, last - float(t)))
                last = float(t)
        return r

    def text_load(self, delta=0.2):
        r = []
        with open(self.input, "r") as f:
            data = f.read()
        for c in data:
            scan = get_scan_code(c)
            if scan is not None:
                r.append((scan, delta))
                r.append((Keyboard.RELEASE, delta))
            else:
                print("WRN: Unable to interpret %c (0x%02x)" % (c, ord(c)))
        return r

    def run(self):
        self.init()
        time.sleep(2)
        for scan, pause in self.load():
            self.send_event(scan)
            time.sleep(pause)
        self.disconnect()


if __name__ == "__main__":
    parser = RubberDucky.create_arg_parser()
    args = parser.parse_args()

    ducky = RubberDucky(args)
    ducky.run()
