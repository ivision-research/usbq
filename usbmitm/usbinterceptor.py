#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  USBInterceptor

"""

import os
import sys
import logging

try:
    import argparse
except:
    print("python-argparse is needed")
    sys.exit(1)


def LinkCommunication(usb, device, host):
    USBInterceptor.device = device
    USBInterceptor.host = host
    return usb


# class USBInteceptor_metaclass(type):
#     def __new__(cls, name, bases, dct):
#         if "DEVICE" in dct:
#             dct["device"] = dct[


class USBInterceptor(object):
    _desc_ = "N/A"

    @classmethod
    def create_arg_parser(cls):
        parser = argparse.ArgumentParser(description="USBInterceptor")
        if cls.HOST:
            cls.HOST.create_arg_parser(parser)
        if cls.DEVICE:
            cls.DEVICE.create_arg_parser(parser)
        cls.create_arg_subparser(parser)
        return parser

    @classmethod
    def create_arg_subparser(cls, parser):
        return parser

    def __init__(self, args):
        self.args = args
        if self.DEVICE:
            self.device = self.DEVICE(args)
        else:
            self.device = None
        if self.HOST:
            self.host = self.HOST(args)
        else:
            self.host = None

    def onReceiveDevice(self, data):
        pass

    def onReceiveHost(self, data):
        pass

    def run(self):
        pass


class USBTermination(object):
    def __init__(self, args, device=True):
        self.args = args
        self.device = device

    def is_host(self):
        return not self.device

    def is_device(self):
        return self.device

    def read(self):
        pass

    def write(self, data):
        pass


if __name__ == "__main__":
    from udp import *

    c = LinkCommunication(USBInterceptor, UDPForwarder)
    parser = c.create_arg_parser()
    args = parser.parse_args()
    x = c(args)
