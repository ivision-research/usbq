#!/usr/bin/env python

from threading import Lock
from collections import defaultdict

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.base import Injecter
from usbmitm.dissect.usb import *


class USBDevice(Injecter):
    """ Simulate an USBDevice """
    def __init__(self,args,ident):
        super(USBDevice,self).__init__(args,ident.to_new_identity())
        self.identity = ident
        self.ep0 = USBEp(epnum=0,eptype=0,epdir=0)
        self.conf_lock = Lock()
        self.configured = False

    def wait_for_configuration(self):
        self.conf_lock.acquire()
        self.conf_lock.release()

    def set_configuration(self,n):
        self.configured = True
        self.conf_lock.release()

    def need_configuration(self):
        self.conf_lock.acquire()

    def init(self):
        super(USBDevice,self).init()
        self.configured = False
        self.need_configuration()
        self.wait_for_configuration()

    def recv_usb(self,msg):
        """ Function called when a USB message is received : type(msg) == USBMessageRequest """
        super(USBDevice,self).recv_usb(msg)
        tmsg = {0:"ctrl",1:"iso",2:"bulk",3:"int"}
        tdir = {0:"in",1:"out"}
        f = "recv_%s%u%s" % (tmsg[msg.ep.eptype],msg.ep.epnum,tdir[msg.ep.epdir])

        if hasattr(self,f):
            getattr(self,f)(msg)
        else:
            self.recv_data_usb(msg)

    def recv_ctrl0in(self,msg):
        """ Function called when a msg on EP0IN is received """
        if msg.request is not None:
            if msg.request.bRequest == 6 and msg.request.bDescriptorType == DEVICE_DESCRIPTOR: # GetDevice:
                if self.configured:
                    self.configured = False
                    self.need_configuration()
            response = self.identity.from_request(msg.request)
            if response:
                msg = USBMessageResponse(ep=self.ep0,request=msg.request,response=response)
                self.send_usb(msg)
            else:
                func = "recv_ctrl0in_data"
                if hasattr(self,func):
                    getattr(self,func)(msg)

    def recv_ctrl0out(self,msg):
        """ Function called when a msg on EP0OUT is received """
        if isinstance(msg.request,SetConfiguration):
            self.set_configuration(0)
        elif isinstance(msg.request,SetIDLE):
            pass
        else:
            func = "recv_ctrl0out_data"
            if hasattr(self,func):
                getattr(self,func)(msg)

        # To be removed since usbq 0.2
        # self.send_ack(msg)

    def is_handle(self,req):
        return isinstance(req,SetIDLE) or isinstance(req,SetConfiguration) or self.identity.from_request(req) is not None

    def send_in_data(self,msg):
        self.send_usb(msg)

    def recv_data_usb(msg):
        pass
