#!/usr/bin/env python

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.base import Injecter


class Endpoint(object):
    def __init__(self,epnum=0,eptype=CTRL,epdir=OUT,maxpkt=64,interval=0):
        self.epnum = epnum
        self.eptype = eptype
        self.epdir = epdir
        self.maxpkt = maxpkt
        self.interval = interval

    def descriptor(self):
        addr = bEndpointAddress(direction=self.epdir,endpoint_number=self.epnum)
        attr = bmAttributes(transfert=self.eptype)
        return EndpointDescriptor(bEndpointAddress=addr,bmAttributes=attr,wMaxPacketSize=self.maxpkt,bInterval=self.interval)
