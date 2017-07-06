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
from usbmitm.utils.utils import *
from usbmitm.base import Forwarder

from usbmitm.dissect.usbmitm_proto import *

classid = {"hid":HID,"mass_storage":MASS_STORAGE}

def get_class(cls):
    try:
        val = int(cls)
    except ValueError:
        try:
            val = classid[cls]
        except KeyError:
            print "ERR: class %s not found" % (cls,)
            sys.exit(0)
    return val

def error(s):
    print colorize(s,Color.red)

def valid(s):
    print colorize(s,Color.green)

class Firewall(Forwarder):
    _desc_ = "USB Firewall"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    @classmethod
    def create_arg_subparser(cls,parser):
        parser.add_argument("--product-id","-pid",metavar="PRODUCT_ID",type=lambda x:int(x,16),help="Allow product ID")
        parser.add_argument("--vendor-id","-vid",metavar="VENDOR_ID",type=lambda x:int(x,16),help="Allow vendor ID")
        parser.add_argument("--class-id","-cls",metavar="CLASS_ID",type=get_class,help="Allow class (integer or string: [%s])" % (",".join(classid.keys(),)))
        parser.add_argument("--filtering",metavar="FILTERING_RULE",help="Filtering rule")

    def __init__(self,args):
        super(Firewall,self).__init__(args)
        self.pid = args.product_id
        self.vid = args.vendor_id
        self.class_id = args.class_id
        self.filtering = args.filtering
        self.reset()

    def reset(self):
        self.passthrough = False
        self.device_desc = None
        self.conf_desc = None

    def clean_descriptors(self,desc):
        """ For now NEW_DEVICE msg only embeds Device, Configuration, Interface and EndpointDescriptor """
        for d in desc:
            if type(desc) not in (InterfaceDescriptor,EndpointDescriptor):
                desc.remove(d)
        return desc

    def hookDevice(self,data):
        """ Called each time we receive device packet """
        try:
            msg = USBMessageDevice(data)
            if msg.type == 2: # Management
                self.hook_management(msg.content)

            # Just to be sure that device won't change its behavior
            # During two requests
            elif msg.type == 0: # Data
                msg = msg.content
                if msg.ep.is_ctrl_0():
                    if type(msg.request) is GetDescriptor and msg.request.bDescriptorType == DEVICE_DESCRIPTOR and self.device_desc != str(msg.response):
                        msg.request.show()
                        error("Device descriptor modifications... resetting and blocking")
                        self.reset()
                        self.reset_to_host()
                    if type(msg.response) is ConfigurationDescriptor:
                        msg.response.descriptors = self.clean_descriptors(msg.response.descriptors)
                        sdata = str(msg.response)
                        if len(sdata) > 9 and self.conf_desc != sdata:
                            error("Configuration descriptor modifications... resetting and blocking")
                            self.reset()
                            self.reset_to_host()

            if self.passthrough:
                return data
        except:
            traceback.print_exc()

    def hook_management(self,msg):
        """ Analyse NEW_DEVICE packet and RESET packet """
        if msg.management_type == 0:
            if self.passthrough:
                print "Device disconnection, blocking..."
                self.reset_to_host()
            self.reset()
        elif msg.management_type == 1:
            self.do_filtering(msg.management_content)
            self.device_desc = str(msg.management_content.device)
            msg.management_content.configuration.descriptors = self.clean_descriptors(msg.management_content.configuration.descriptors)
            self.conf_desc = str(msg.management_content.configuration)

    def do_filtering(self,msg):
        """ Analyse NEW_DEVICE packet to allow or block it """
        if self.filtering:
            if eval(self.filtering):
                valid("Allowing new device...")
                self.passthrough = True
            else:
                error("Not valid, blocking: does not match rule")
                return
        else:
            if (self.pid and self.msg.idProduct != self.pid) or \
               (self.vid and self.msg.idVendor != self.vid):
                print "Not valid, blocking: bad pid/vid"
                return
            if self.class_id:
                intf_found = False
                for desc in msg.configuration.descriptors:
                    if type(desc) is InterfaceDescriptor:
                        if self.class_id != desc.bInterfaceClass:
                            error("Not valid, blocking: bad interface found")
                            return
                        else:
                            intf_found = True
                if not intf_found:
                    error("Not valid, blocking: no valid interface found")
                    return
        valid("Allowing new device...")
        self.passthrough = True


if __name__ == "__main__":
    parser = Firewall.create_arg_parser()
    args = parser.parse_args()
    fw = Firewall(args)
    fw.run()
