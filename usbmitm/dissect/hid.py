#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.fields import *
from scapy.packet import Packet

from fields import *
from usb import *

HID_PROTOCOL_KEYOARD = 1
HID_PROTOCOL_MOUSE   = 2

class HIDReportDescriptor(USBPacket):
    fields_desc = [
        ByteField("bDescriptorType",0x22),
        LEShortField("wDescriptorLength",0x41),
        ]

    def desc(self):
        return "HIDReportDescriptor sz:%u" % (self.wDescriptorLength,)

class HIDDescriptor(USBDescriptor):
    name = "HIDDescriptor"

    fields_desc = [
        ByteField("bLength",None),
        ByteEnumField("bDescriptorType",0x21,urb_bDescriptorType),
        ShortField("bcdHID",0x1001),
        ByteField("bCountryCode",0),
        ByteField("bNumDescriptors",1),
        PacketListField("descriptors",[HIDReportDescriptor()],HIDReportDescriptor,count_from=lambda p:p.bNumDescriptors)
    ]

    def post_build(self,p,pay):
        if self.bLength is None:
            p = struct.pack("B",len(p)) + p[1:]
        return p+pay

    def desc(self):
        return "HIDDescriptor sz:%u nb_report:%u [%s]" % (self.bLength,self.bNumDescriptors," ".join(map(lambda x:x.desc(),self.descriptors)))

class ReportDescriptor(USBPacket):
    fields_desc = [
        StrField("data","05010906a101050719e029e71500250175019508810295017508810195037501050819012903910295057501910195067508150026ff00050719002aff008100c0".decode("hex"))
    ]
