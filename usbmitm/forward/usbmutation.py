#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Receiver
"""

import sys
import struct
import traceback
import time
import random

from threading import Timer

try:
    import argparse
except:
    print "python-argparse is needed"
    sys.exit(1)

from usbmitm.comm.udp import USBSocketDevice,USBSocketHost
from usbmitm.utils import *
from dissector import Dissector

from usbmitm.dissect.usbmitm_proto import *
import usbmitm.device.azerty as keyboard

# Taken from scapy : scapy/utils.py
def corrupt_bytes(s, p=0.01, n=None):
    """Corrupt a given percentage or number of bytes from a string"""
    s = array.array("B",str(s))
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i] = (s[i]+random.randint(1,255))%256
    return s.tostring()

# Taken from scapy : scapy/utils.py
def corrupt_bits(s, p=0.01, n=None):
    """Flip a given percentage or number of bits from a string"""
    s = array.array("B",str(s))
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i/8] ^= 1 << (i%8)
    return s.tostring()

class USBMutation(Dissector):
    """ Program used to add mutation inside USB communication """
    _desc_ = "USB Mutation"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    @classmethod
    def create_arg_subparser(cls,parser):
        parser.add_argument("--mutation-host","-H",action="store_true",help="Apply mutation on data sent by host")
        parser.add_argument("--mutation-device","-D",action="store_true",help="Apply mutation on data sent by device")
        parser.add_argument("--timer","-t",metavar="SECONDS",type=int,default=10,help="Number of seconds before reloading communication")
        parser.add_argument("--seed",metavar="SEED",type=int,help="Set seed for random values to be reproductible")
        parser.add_argument("--bytes","-B",action="store_true",help="If set then corrupt byte will be set instead of corrupt bits")
        parser.add_argument("--percentage-pkt","-P",metavar="PERCENTAGE",default=0.01,type=float,help="Percentage of packet modified")
        parser.add_argument("--number","-n",metavar="NUMBER",default=None,type=int,help="Number of bits/bytes fuzzed inside a packet")
        parser.add_argument("--percentage","-c",metavar="PERCENTAGE",default=0.01,type=float,help="Percentage of bits/bytes fuzzed inside a packet (will be override by number if set)")
        parser.add_argument("endpoints",metavar="ENDPOINTS",nargs="*",help="Endpoints to fuzz: ctr1in,bul0out,int1out... (empty for all) ")

    def __init__(self,args):
        super(USBMutation,self).__init__(args)
        self.mutation_from_host = args.mutation_host
        self.mutation_from_device = args.mutation_device
        self.timer_device = None
        self.timer_host = None

        if args.bytes:
            self.corrupt = corrupt_bytes
        else:
            self.corrupt = corrupt_bits

        self.number = args.number
        self.percentage = args.percentage
        self.percentage_pkt = args.percentage_pkt

        # To be reproductible
        if not args.seed is None:
            random.seed(args.seed)

        self.endpoints = args.endpoints

    def fail_device(self):
        self.reload_communication()

    def fail_host(self):
        self.reload_communication()

    def reload_communication(self):
        print "Reloading device..."
        self.reset_to_device()
        self.reload_to_device()

    def shall_modify(self,msg):
        """ Return True if msg shall be modified """
        return self.match(msg.ep) and float(random.randint(0,100)) < args.percentage_pkt

    def match(self,ep):
        """ Return True if ep should be modified """
        if len(self.endpoints) == 0:
            return True
        else:
            ht = {0:"ctrl",1:"isoc",2:"bulk",3:"int"}
            hd = {0:"in",1:"out"}
            eps = "%s%u%s" % (ht[ep.eptype],ep.epnum,hd[ep.epdir])
            return eps in self.endpoints

    def hook(self,data):
        try:
            print "."
            data = self.do_corrupt(data)
        except:
            traceback.print_exc()
        return data

    def hookUSBDevice(self,msg):

        if self.timer_device:
            self.timer_device.cancel()
        self.timer_device = Timer(self.args.timer,self.fail_device)
        self.timer_device.start()

        if self.mutation_from_device and self.shall_modify(msg):
            self.timer_device.cancel()
            if msg.response is not None:
                data = str(msg.response)+msg.data
            else:
                data = msg.data
            return str(msg.ep) + self.hook(data)
        return msg

    def hookUSBHost(self,msg):
        if self.mutation_from_host and self.shall_modify(msg):
            if hasattr(msg,"request"):
                data = str(msg.request)+msg.data
            else:
                data = msg.data
            return data
        return msg

    def do_corrupt(self,data):
        return self.corrupt(data,self.percentage,self.number)


if __name__ == "__main__":
    parser = USBMutation.create_arg_parser()
    args = parser.parse_args()
    mutation = USBMutation(args)
    mutation.run()
