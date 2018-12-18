#!/usr/bin/env python

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.host.host import USBHost


class USBHid(USBHost):
    """ Handle HID devices """

    def __init__(self, args):
        super(USBHid, self).__init__(
            args,
            [
                DEVICE_DESCRIPTOR,
                CONFIGURATION_DESCRIPTOR,
                STRING_DESCRIPTOR,
                HID_REPORT_DESCRIPTOR,
            ],
        )

    def match_request(self, req, rep):
        if req == HID_REPORT_DESCRIPTOR:
            return True
        return rep.bDescriptorType == req

    def recv_data_usb(self, msg):
        print("RECV: %r" % (msg,))


if __name__ == "__main__":
    parser = USBHid.create_arg_parser()
    args = parser.parse_args()

    hid = USBHid(args)
    hid.run()
