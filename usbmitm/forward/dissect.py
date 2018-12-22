#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Receiver
"""

import sys
import struct
import traceback

try:
    import argparse
except:
    print("python-argparse is needed")
    sys.exit(1)

from binascii import hexlify
from scapy.packet import Packet

from usbmitm.comm.udp import USBSocketDevice, USBSocketHost
from usbmitm.utils.utils import *
from usbmitm.base import Forwarder

from usbmitm.dissect.usbmitm_proto import *

abv_type = {"CONTROL": "C", "BULK": "B", "INTERRUPT": "I", "ISOCHRONOUS": "S"}

abv_dir = {"IN": "i", "OUT": "o"}


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


def extract_usb_part(data):
    return data[8:]


def lhex(msg):
    if issubclass(type(msg), Packet):
        return repr(msg)
    else:
        return hexlify(msg).decode()


class Dissector(Forwarder):
    _desc_ = "USB Dissector"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument(
            "--no-log-device", action="store_true", help="Print message get from Device"
        )
        parser.add_argument(
            "--no-log-host", action="store_true", help="Print responses get from Host"
        )
        parser.add_argument(
            "--debug-mitm", action="store_true", help="Print all USBMitm packet"
        )
        parser.add_argument(
            "--dissect", action="store_true", help="Dissect USB Packets"
        )
        parser.add_argument(
            "--full", action="store_true", help="Dissect Full USB Packets"
        )

    def __init__(self, args):
        Forwarder.__init__(self, args)
        self.log_device = True
        self.log_host = True
        if args.no_log_device:
            self.log_device = False
        if args.no_log_host:
            self.log_host = False
        self.debug_mitm = args.debug_mitm
        self.full = args.full

        func = (
            lambda d, ep: "%s%s%u: %s"
            % (abv_type[ep[1]], abv_dir[ep[2]], ep[0], self._output(d))
            if ep is not None
            else "MNGT: %s" % (self._output(d),)
        )

        if self.debug_mitm:
            if args.dissect:
                self.fmt = (
                    lambda d, ep: func(USBMessageDevice(d), ep),
                    lambda d, ep: func(USBMessageHost(d), ep),
                )
            else:
                self.fmt = (
                    lambda d, ep: func(lhex(d), ep),
                    lambda d, ep: func(lhex(d), ep),
                )
        else:
            if args.dissect:
                self.fmt = (
                    lambda d, ep: func(
                        USBMessageResponse(extract_usb_part(d)).get_usb_payload(), ep
                    )
                    if is_usb_msg(d)
                    else None,
                    lambda d, ep: func(
                        USBMessageRequest(extract_usb_part(d)).get_usb_payload(), ep
                    )
                    if is_usb_msg(d)
                    else None,
                )
            else:
                self.fmt = (
                    lambda d, ep: func(lhex(extract_usb_part(d)), ep)
                    if is_usb_msg(d)
                    else None,
                    lambda d, ep: func(lhex(extract_usb_part(d)), ep)
                    if is_usb_msg(d)
                    else None,
                )

    def _output(self, data):
        if type(data) is str or self.full:
            return "%r" % (data,)
        else:
            return lhex(data)

    def output_device(self, data):
        s = self.msg_colorize(data, self.fmt[0])
        if s is not None:
            print("> %s" % (s,))

    def output_host(self, data):
        s = self.msg_colorize(data, self.fmt[1])
        if s is not None:
            print("< %s" % (s,))

    def msg_colorize(self, data, f):
        colors = {
            ("CONTROL", "IN"): Color.red,
            ("CONTROL", "OUT"): Color.purple,
            ("INTERRUPT", "IN"): Color.blue,
            ("INTERRUPT", "OUT"): Color.cyan,
            ("BULK", "IN"): Color.green,
            ("BULK", "OUT"): Color.yellow,
            ("ISOCHRONOUS", "IN"): 47,
            ("ISOCHRONOUS", "OUT"): 172,
        }

        ep = extract_ep(data)

        s = f(data, ep)
        if s is None:
            return s

        if not is_usb_msg(data):
            color = Color.grey + Color.bold
        else:
            color = colors.get(ep[1:], Color.normal)

        return colorize(s, color)

    def hookDevice(self, data):
        try:
            if self.log_device:
                self.output_device(data)
        except:
            print("Output Error")
            traceback.print_exc()
        return data

    def hookHost(self, data):
        try:
            if self.log_host:
                self.output_host(data)
        except:
            print("Output Error")
            traceback.print_exc()
        return data


if __name__ == "__main__":
    parser = Dissector.create_arg_parser()
    args = parser.parse_args()
    dissect = Dissector(args)
    dissect.run()
