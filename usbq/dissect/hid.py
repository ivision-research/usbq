# -*- coding: utf-8 -*-

from scapy.fields import (
    ByteEnumField,
    ByteField,
    LEShortField,
    PacketListField,
    ShortField,
    StrField,
    struct,
)

from ..defs import USBDefs
from .usb import USBDescriptor, USBPacket

__all__ = ['HIDReportDescriptor', 'HIDDescriptor', 'ReportDescriptor']


class HIDReportDescriptor(USBPacket):
    fields_desc = [
        ByteField("bDescriptorType", USBDefs.DescriptorType.HID_REPORT_DESCRIPTOR),
        LEShortField("wDescriptorLength", 0x41),
    ]

    def desc(self):
        return "HIDReportDescriptor sz:%u" % (self.wDescriptorLength,)


class HIDDescriptor(USBDescriptor):
    name = "HIDDescriptor"

    fields_desc = [
        ByteField("bLength", None),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.HID_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        ShortField("bcdHID", 0x1001),
        ByteField("bCountryCode", 0),
        ByteField("bNumDescriptors", 1),
        PacketListField(
            "descriptors",
            [HIDReportDescriptor()],
            HIDReportDescriptor,
            count_from=lambda p: p.bNumDescriptors,
        ),
    ]

    def post_build(self, p, pay):
        if self.bLength is None:
            p = struct.pack("B", len(p)) + p[1:]
        return p + pay

    def desc(self):
        return "HIDDescriptor sz:%u nb_report:%u [%s]" % (
            self.bLength,
            self.bNumDescriptors,
            " ".join([x.desc() for x in self.descriptors]),
        )


class ReportDescriptor(USBPacket):
    fields_desc = [
        StrField(
            "data",
            int(
                "05010906a101050719e029e71500250175019508810295017508810195037501050819012903910295057501910195067508150026ff00050719002aff008100c0",
                16,
            ),
        )
    ]
