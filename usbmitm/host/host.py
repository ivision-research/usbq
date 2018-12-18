#!/usr/bin/env python

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.base import Receiver


class USBHost(Receiver):
    """ Host handling Enumeration phase """

    def __init__(
        self,
        args,
        descriptors_needed=[
            DEVICE_DESCRIPTOR,
            CONFIGURATION_DESCRIPTOR,
            STRING_DESCRIPTOR,
        ],
    ):
        super(USBHost, self).__init__(args)
        self.descriptors_needed = descriptors_needed
        self.descriptors = {}
        self.ep0in = USBEp(epnum=0, eptype=CTRL, epdir=PROTO_IN)
        self.ep0out = USBEp(epnum=0, eptype=CTRL, epdir=PROTO_OUT)

    def recv_management(self, msg):
        if type(msg.management_content) is ManagementNewDevice:
            self.device_descriptors = {}
            self.do_first_request()

    def recv_usb(self, msg):
        # Will be handled in other classes
        if msg.ep.is_ctrl_0() and self.match_request(self.last_req, msg.response):
            self.recv_desc(msg.response)
            if self.is_enumeration_finished():
                self.data_exchange()
        else:
            self.recv_data_usb(msg)

    def recv_desc(self, rep):
        self.descriptors[self.last_req] = rep

        f = "get_next_req_%s" % (urb_bDescriptorType[self.last_req],)
        if hasattr(self, f):
            next_req = getattr(self, f)(rep)
            if next_req is None:
                return
        else:
            try:
                new_index = self.descriptors_needed.index(rep.bDescriptorType) + 1
            except ValueError:
                return
            next_req = GetDescriptor(
                bDescriptorType=self.descriptors_needed[new_index], wLength=255
            )

        self.do_request(next_req)

    def get_next_req_device(self, rep):
        """ Device Descriptor reception """
        return GetDescriptor(bDescriptorType=CONFIGURATION_DESCRIPTOR, wLength=9)

    def get_next_req_configuration(self, rep):
        """ Configuration descriptor reception """
        if len(rep) != rep.wTotalLength:
            req = GetDescriptor(
                bDescriptorType=CONFIGURATION_DESCRIPTOR, wLength=rep.wTotalLength
            )
        else:
            req = GetDescriptor(bDescriptorType=STRING_DESCRIPTOR, wLength=255)
        return req

    def get_next_req_string(self, rep):
        """ String descriptor reception """
        self.set_request(SetConfiguration())

        try:
            new_index = self.descriptors_needed.index(rep.bDescriptorType) + 1
        except ValueError:
            return None

        next_req = GetDescriptor(
            bDescriptorType=self.descriptors_needed[new_index], wLength=255
        )
        return next_req

    def match_request(self, req, rep):
        return rep.bDescriptorType == req

    def recv_data_usb(self, msg):
        pass

    def is_enumeration_finished(self):
        """ Return True if enumeration is finished """
        for desc in self.descriptors_needed:
            if desc not in self.descriptors:
                return False
        return True

    def do_first_request(self):
        self.do_request(GetDescriptor(bDescriptorType=DEVICE_DESCRIPTOR, wLength=64))

    def do_request(self, req):
        self.last_req = req.bDescriptorType
        self.send_usb(USBMessageRequest(ep=self.ep0in, request=req))

    def set_request(self, req):
        self.send_usb(USBMessageRequest(ep=self.ep0out, request=req))

    def data_exchange(self):
        pass


if __name__ == "__main__":
    parser = USBHost.create_arg_parser()
    args = parser.parse_args()

    host = USBHost(args)
    host.run()
