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
from dissector import Dissector

from usbmitm.utils.speed import ls2hs_interval

from usbmitm.dissect.usbmitm_proto import *
import usbmitm.device.azerty as keyboard


class FixLowSpeed(Dissector):
    """ USBIQUITOUS board is a high speed board, so there are problems when
    an low speed device is connected and forwarded. This forwarders fix descriptors to
    work correctly """

    _desc_ = "USB Keylogger"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument(
            "--no-pkt-sz",
            action="store_true",
            help="Do not fix DeviceDescriptor max packet size",
        )
        parser.add_argument(
            "--no-pkt-interval",
            action="store_true",
            help="Do not fix EndpointDescriptors interval",
        )
        parser.add_argument(
            "--no-usb-version", action="store_true", help="Do not usb version"
        )

    def __init__(self, args):
        super(FixLowSpeed, self).__init__(args)
        self.pkt_sz = not args.no_pkt_sz
        self.pkt_interval = not args.no_pkt_interval
        self.usb_version = not args.no_usb_version
        self.speed = 0

    def hookMANAGEMENTDevice(self, msg):
        if msg.management_type == 1:  # New Device
            self.speed = msg.management_content.speed
        return msg

    def is_low_speed(self):
        return self.speed == 1

    def is_full_speed(self):
        return self.speed == 2

    def hookUSBDevice(self, msg):
        if self.is_low_speed() or self.is_full_speed():
            msg = self.fix(msg)
        return msg

    def fix(self, msg):
        if msg.ep.is_ctrl_0():
            if isinstance(msg.response, DeviceDescriptor):
                if self.pkt_sz:
                    msg.response = self.fix_pkt_size(msg.response)
                if self.usb_version:
                    msg.response = self.fix_usb_version(msg.response)

            if isinstance(msg.response, ConfigurationDescriptor) and self.pkt_interval:
                msg.response = self.fix_pkt_interval(msg.response)
        return msg

    def fix_pkt_size(self, device_descriptor):
        """ Fix maxPacketSize of DeviceDescriptor """
        device_descriptor.bMaxPacketSize = 64
        return device_descriptor

    def fix_pkt_interval(self, configuration_descriptor):
        """ Fix interval of EndpointDescriptors
        Board is acting as a High speed device, so bInterval is interpreted
        as a polling rate equal to (bInterval-1) units with units equat to 125µs.
        Value is then changed to match behavior of a low speed device
        """
        if len(configuration_descriptor.descriptors) == 0:
            return configuration_descriptor
        for endpoint_descriptor in configuration_descriptor.descriptors:
            if isinstance(endpoint_descriptor, EndpointDescriptor):
                endpoint_descriptor.bInterval = ls2hs_interval(
                    endpoint_descriptor.bInterval
                )
        return configuration_descriptor

    def fix_usb_version(self, device_descriptor):
        """ Fix maxPacketSize of DeviceDescriptor """
        device_descriptor.bcdUSB = 0x200
        return device_descriptor


if __name__ == "__main__":
    parser = FixLowSpeed.create_arg_parser()
    args = parser.parse_args()
    fix = FixLowSpeed(args)
    fix.run()
