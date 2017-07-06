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
    print "python-argparse is needed"
    sys.exit(1)

from usbmitm.comm.udp import USBSocketDevice,USBSocketHost
from usbmitm.base import Forwarder

from usbmitm.dissect.usbmitm_proto import *

class Dissector(Forwarder):
    _desc_ = "USB Dissector"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    def __init__(self,args):
        Forwarder.__init__(self,args)

    def hookHost(self,data):
        try:
            msg = USBMessageHost(data)
            func = "hook%sHost" % (mitm_type[msg.type],)
            if hasattr(self,func):
                new_content = getattr(self,func)(msg.content)
                msg.len = None
                msg.content = new_content
            data = str(msg)
        except:
            traceback.print_exc()
        return data

    def hookDevice(self,data):
        try:
            msg = USBMessageDevice(data)
            func = "hook%sDevice" % (mitm_type[msg.type],)
            if hasattr(self,func):
                new_content = getattr(self,func)(msg.content)
                msg.len = None
                msg.content = new_content
            data = str(msg)
        except:
            traceback.print_exc()
        return data

if __name__ == "__main__":
    parser = Dissector.create_arg_parser()
    args = parser.parse_args()
    dissector = Dissector(args)
    dissector.run()
