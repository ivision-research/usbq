#!/usr/bin/env python

import sys
from threading import Lock

from device import USBDevice
from usbmitm.dissect.usbmitm_proto import *

class HIDDevice(USBDevice):
    def __init__(self,args,ident,report_descriptor):
        super(HIDDevice,self).__init__(args,ident)
        if type(report_descriptor) is not list:
            report_descriptor = {0:report_descriptor}
        self.report_descriptor = report_descriptor
        self.hid_report_sent = Lock()
        self.need_hid_report()

    def recv_ctrl0in(self,msg):
        """ Function called when a msg on EP0IN is received """
        if msg.request is not None:
            if msg.request.bDescriptorType == 34:
                lang = msg.request.language_id
                if not lang in self.report_descriptor:
                    print "WRN: Unable to get report_descriptor for language %u using 0" % (msg.request.language_id,)
                    lang = 0
                msg = USBMessageResponse(ep=self.ep0,request=msg.request,response=self.report_descriptor[lang])
                self.send_usb(msg)
                self.hid_request_received()
            else:
                super(HIDDevice,self).recv_ctrl0in(msg)

    def wait_for_hid_report(self):
        self.hid_report_sent.acquire()
        self.hid_report_sent.release()

    def hid_request_received(self):
        self.hid_report_sent.release()

    def need_hid_report(self):
        self.hid_report_sent.acquire()

    def init(self):
        super(HIDDevice,self).init()
        self.wait_for_hid_report()

    def disconnect(self):
        self.need_hid_report()
        super(HIDDevice,self).disconnect()
