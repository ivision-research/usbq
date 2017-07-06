#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Receiver
"""

import sys
import struct
import traceback
import time

from threading import Lock

from scapy.utils import RawPcapWriter

try:
    import argparse
except:
    print "python-argparse is needed"
    sys.exit(1)

from usbmitm.utils import *
from dissector import Dissector
from usbmitm.dissect.usbpcap import *

from usbmitm.dissect.usbmitm_proto import *
import usbmitm.device.azerty as keyboard

def usb_to_usbpcap(msg):
    pcap = USBPcap()
    pcap.urb_transfert = eptype_to_pcap_type[msg.ep.eptype]
    pcap.endpoint_direction = OUT if msg.ep.epdir == PROTO_OUT else IN
    pcap.endpoint_number = msg.ep.epnum
    pcap.garbage = "\x00"*24
    return pcap

def usbdev_to_usbpcap(msg):
    """ Transform a USBMessageDevice message to a USBPcap message """
    pcap = usb_to_usbpcap(msg)
    pcap.urb_type = "C"
    pcap.device_setup_request = 0x2d # No relevant
    pcap.data_present = 0 if msg.ep.eptype == 1 else 0x3e
    if msg.ep.is_ctrl_0() and msg.ep.epdir == PROTO_IN:
        pcap.descriptor = msg.response
        pcap.urb_length = len(msg.response)+len(msg.data)
        pcap.data_length = len(msg.response)+len(msg.data)
    else:
        pcap.descriptor = None
        pcap.urb_length = len(msg.data)
        pcap.data_length = len(msg.data)
    pcap.urb_setup = None
    pcap.data = msg.data
    return pcap

def usbhost_to_usbpcap(msg):
    """ Transform a USBMessageHost message to a USBPcap message """
    pcap = usb_to_usbpcap(msg)
    pcap.urb_type = "S"
    pcap.device_setup_request = 0 # Relevant
    pcap.data_present = 0x3e if msg.ep.eptype == 1 else 0
    if msg.ep.is_ctrl_0() and msg.ep.epdir == PROTO_IN:
        pcap.urb_length = msg.request.wLength
        pcap.data_length = 0
    else:
        pcap.descriptor = None
        pcap.urb_length = len(msg.data)
        pcap.data_length = len(msg.data)
    pcap.urb_setup = msg.request
    pcap.data = msg.data
    return pcap


def req_from_msg(msg):
    """ Find request that has generated msg """
    req = usb_to_usbpcap(msg)
    pcap.urb_type = "S"
    req.status = -115
    req.urb_length = len(msg.data)
    req.data_length = 0
    req.urb_setup = None
    return req

def ack_from_msg(msg):
    """ Find ack for the msg """
    ack = usb_to_usbpcap(msg)
    ack.urb_type = "C"
    if msg.ep.eptype == CTRL and msg.ep.epdir == PROTO_OUT:
        ack.urb_length = msg.request.wLength
    else:
        ack.urb_length = len(msg.data)
    ack.data_length = 0
    ack.urb_setup = None
    return ack


class USBPcapWriter(Dissector):
    """ """
    _desc_ = "USB Pcap Writer"

    @classmethod
    def create_arg_subparser(cls,parser):
        parser.add_argument("--output","-o",metavar="PCAP_FILE",help="PCAP file")

    def __init__(self,args):
        super(USBPcapWriter,self).__init__(args)
        self.pcap = RawPcapWriter(args.output,linktype=220,sync=True)
        self.lock = Lock()

    def hookUSBDevice(self,msg):
        # We do not receive REQUEST from host if type is not CTRL
        if msg.ep.eptype != CTRL:
            req = req_from_msg(msg)
            self.write_pcap(req)

        pkt = usbdev_to_usbpcap(msg)
        self.write_pcap(pkt)
        return msg

    def hookUSBHost(self,msg):
        pkt = usbhost_to_usbpcap(msg)
        self.write_pcap(pkt)

        # We do not receive ACK from device for OUT data
        if msg.ep.epdir == PROTO_OUT:
            ack = ack_from_msg(msg)
            self.write_pcap(ack)
        return msg

    def write_pcap(self,msg):
        self.lock.acquire()
        self.pcap.write(str(msg))
        self.lock.release()


if __name__ == "__main__":
    parser = USBPcapWriter.create_arg_parser()
    args = parser.parse_args()
    pcap = USBPcapWriter(args)
    pcap.run()
