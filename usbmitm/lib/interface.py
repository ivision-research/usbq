#!/usr/bin/env python

from usbmitm.dissect.usb import *
from usbmitm.lib.endpoint import Endpoint


class Interface(object):
    def __init__(self, descriptors, cls=0, subcls=0, proto=0):
        self.cls = cls
        self.subcls = subcls
        self.proto = proto
        self.descriptors = descriptors

    def descriptor(self):
        desc = [
            InterfaceDescriptor(
                bInterfaceClass=self.cls,
                bInterfaceSubClass=self.subcls,
                bInterfaceProtocol=self.proto,
            )
        ]
        nbep = 0
        for d in self.descriptors:
            if type(d) is Endpoint:
                desc.append(d.descriptor())
                nbep += 1
            else:
                desc.append(d)
        desc[0].bNumEndpoint = nbep
        return desc
