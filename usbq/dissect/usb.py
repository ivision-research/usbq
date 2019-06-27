# -*- coding: utf-8 -*-

from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    LEShortField,
    PacketField,
    PacketListField,
    ShortEnumField,
    StrField,
    StrLenField,
    XByteField,
    struct,
)
from scapy.packet import Packet

from ..defs import URBDefs, USBDefs
from .fields import (
    BytesFixedLenField,
    UnicodeStringLenField,
    XLEShortEnumField,
)

__all__ = [
    'bEndpointAddress',
    'bmAttributes',
    'bmRequestType',
    'BOSDescriptor',
    'ConfigurationDescriptor',
    'Descriptor',
    'DeviceDescriptor',
    'EndpointDescriptor',
    'GetDescriptor',
    'GetReport',
    'InterfaceDescriptor',
    'RawDescriptor',
    'RequestDescriptor',
    'SetConfiguration',
    'SetIDLE',
    'SetInterface',
    'StringDescriptor',
    'UnknownDescriptor',
    'URB',
    'USBDescriptor',
    'USBPacket',
]


class USBPacket(Packet):
    def extract_padding(self, s):
        return "", s

    def desc(self):
        return "%s" % (self.__class__.__name__,)


class USBDescriptor(USBPacket):
    def pre_dissect(self, s):
        if hasattr(self, "desc_len"):
            self.desc_len = len(s)
        return s

    def post_build(self, pkt, pay):
        if hasattr(self, "desc_len"):
            return (pkt + pay)[: self.desc_len]
        else:
            return pkt + pay


class bmRequestType(USBPacket):
    fields_desc = [
        BitEnumField(
            "direction", URBDefs.Direction.DEVICE_TO_HOST, 1, URBDefs.Direction.desc
        ),
        BitEnumField("type", URBDefs.Type.STANDARD, 2, URBDefs.Type.desc),
        BitEnumField("recipient", URBDefs.Recipient.DEVICE, 5, URBDefs.Recipient.desc),
    ]


class RequestDescriptor(USBPacket):
    fields_desc = [
        PacketField("bmRequestType", bmRequestType(), bmRequestType),
        ByteField("bRequest", 0),
        LEShortField("wValue", 1),
        LEShortField("wIndex", 0),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "REQ:%u val:%u ind:%u len:%u" % (
            self.bRequest,
            self.wValue,
            self.wIndex,
            self.wLength,
        )


class GetDescriptor(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType", bmRequestType(), bmRequestType),
        ByteEnumField("bRequest", URBDefs.Request.GET_DESCRIPTOR, URBDefs.Request.desc),
        ByteField("descriptor_index", 0),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.DEVICE_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        ShortEnumField(
            "language_id", URBDefs.Language.NONE_SPECIFIED, URBDefs.Language.desc
        ),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "GetDescriptor %s [sz:%u]" % (
            USBDefs.DescriptorType[self.bDescriptorType],
            self.wLength,
        )


class GetReport(RequestDescriptor):
    fields_desc = [
        PacketField(
            "bmRequestType",
            bmRequestType(direction=1, type=1, recipient=1),
            bmRequestType,
        ),
        ByteEnumField("bRequest", URBDefs.Request.GET_REPORT, URBDefs.Request.desc),
        LEShortField("wValue", 0),
        LEShortField("wIndex", 0),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "GetReport"


class SetConfiguration(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType", bmRequestType(direction=0), bmRequestType),
        ByteEnumField(
            "bRequest", URBDefs.Request.SET_CONFIGURATION, URBDefs.Request.desc
        ),
        ByteField("bConfigurationValue", 1),
        LEShortField("wIndex", 0),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "SetConfiguration %u" % (self.bConfigurationValue,)


class SetInterface(RequestDescriptor):
    fields_desc = [
        PacketField(
            "bmRequestType",
            bmRequestType(direction=0, type=0, recipient=1),
            bmRequestType,
        ),
        ByteEnumField("bRequest", URBDefs.Request.SET_INTERFACE, URBDefs.Request.desc),
        LEShortField("bAlternateSetting", 0),  # In fact byte + 1 padding
        LEShortField("wInterface", 1),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "SetInterface intf:%u alt:%u" % (self.wInterface, self.bAlternateSetting)


class SetIDLE(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType", bmRequestType(), bmRequestType),
        ByteEnumField("bRequest", URBDefs.Request.SET_IDLE, URBDefs.Request.desc),
        LEShortField("wValue", 1),
        LEShortField("wIndex", 0),
        LEShortField("wLength", 0),
    ]

    def desc(self):
        return "SetIDLE"


def URB(payload):
    breqtype = payload[0]
    breq = payload[1]
    if breq == 6:
        cls = GetDescriptor
    elif breq == 1:
        cls = GetReport
    elif breqtype == 0 and breq == 9:
        cls = SetConfiguration
    elif breqtype == 0x21 and breq == 10:
        cls = SetIDLE
    elif breqtype == 0 and breq == 0xb:
        cls = SetInterface
    else:
        cls = RequestDescriptor
    return cls(payload)


bDeviceClass = {0: "Device"}
bDeviceProtocol = {0: "See Interface"}
idVendor = {}
idProduct = {}


def Descriptor(payload):
    from .hid import HIDDescriptor, HIDReportDescriptor

    if len(payload) < 2:
        return RawDescriptor(payload)
    desctype = payload[1]
    if desctype == 1:
        l = payload[0]
        if l == 5:
            cls = HIDReportDescriptor
        elif len(payload) != 18:
            cls = RawDescriptor
        else:
            cls = DeviceDescriptor
    elif desctype == USBDefs.DescriptorType.CONFIGURATION_DESCRIPTOR:
        cls = ConfigurationDescriptor
    elif desctype == USBDefs.DescriptorType.STRING_DESCRIPTOR:
        cls = StringDescriptor
    elif desctype == USBDefs.DescriptorType.INTERFACE_DESCRIPTOR:
        cls = InterfaceDescriptor
    elif desctype == USBDefs.DescriptorType.ENDPOINT_DESCRIPTOR:
        cls = EndpointDescriptor
    elif desctype == USBDefs.DescriptorType.BOS_DESCRIPTOR:
        cls = BOSDescriptor
    elif desctype == USBDefs.DescriptorType.HID_DESCRIPTOR:
        cls = HIDDescriptor
    else:
        cls = UnknownDescriptor
    return cls(payload)


class RawDescriptor(USBDescriptor):
    fields_desc = [StrField("raw", "")]


class UnknownDescriptor(USBDescriptor):
    fields_desc = [
        ByteField("bLength", None),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.DEVICE_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        BytesFixedLenField("data", "", length_from=lambda p: p.bLength - 2),
    ]


class DeviceDescriptor(USBDescriptor):
    fields_desc = [
        ByteField("bLength", 18),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.DEVICE_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        LEShortField("bcdUSB", 0x0200),
        ByteEnumField("bDeviceClass", 0, bDeviceClass),
        ByteField("bDeviceSubClass", 0),
        ByteEnumField("bDeviceProtocol", 0, bDeviceProtocol),
        ByteField("bMaxPacketSize", 64),
        XLEShortEnumField("idVendor", 0x6464, idVendor),
        XLEShortEnumField("idProduct", 0x6464, idProduct),
        LEShortField("bcdDevice", 0x0200),
        XByteField("iManufacturer", 1),
        XByteField("iProduct", 2),
        ByteField("iSerialNumber", 3),
        ByteField("bNumConfigurations", 1),
    ]

    def desc(self):
        s = [
            "Device Descriptor vid:%02x pid:%02x maxpkt:%u len:%u"
            % (self.idVendor, self.idProduct, self.bMaxPacketSize, self.bLength)
        ]
        if self.bNumConfigurations != 1:
            s.append("nconf:%u" % (self.bNumConfigurations,))
        return " ".join(s)


class ConfigurationDescriptor(USBDescriptor):
    name = "ConfigurationDescriptor"

    fields_desc = [
        ByteField("bLength", 9),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.CONFIGURATION_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        LEShortField("wTotalLength", None),
        ByteField("bNumInterfaces", 1),
        ByteField("bConfigurationValue", 1),
        ByteField("iConfiguration", 0),
        ByteField("bmAttributes", 0xa0),
        ByteField("bMaxPower", 50),
        PacketListField("descriptors", None, Descriptor),
    ]

    def post_build(self, p, pay):
        if self.wTotalLength is None:
            p = p[:2] + struct.pack("<H", len(p)) + p[4:]
        return p + pay

    def desc(self):
        s = ["Configuration Descriptor nintf:%u" % (self.bNumInterfaces,)]
        for d in self.descriptors:
            s.append(d.desc())
        return "\n   ".join(s)


class StringDescriptor(USBDescriptor):
    fields_desc = [
        FieldLenField(
            "bLength", None, length_of="bString", fmt="B", adjust=lambda pkt, x: x + 2
        ),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.STRING_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        # ConditionalField(LEShortField("wLANGID",0x0409),lambda p:p.bLength==4),
        UnicodeStringLenField(
            "bString", "\x09\x04", length_from=lambda p: p.bLength - 2
        ),
    ]

    def desc(self):
        return "String Descriptor [%s] len:%u" % (self.bString, self.bLength)


bInterfaceClass = {3: "hid", 8: "mass_storage"}


class InterfaceDescriptor(USBDescriptor):
    name = "InterfaceDescriptor"

    fields_desc = [
        ByteField("bLength", 9),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.INTERFACE_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        ByteField("bInterfaceNumber", 0),
        ByteField("bAlternateSetting", 0),
        ByteField("bNumEndpoint", 1),
        ByteEnumField("bInterfaceClass", 3, bInterfaceClass),
        ByteField("bInterfaceSubClass", 1),
        ByteField("bInterfaceProtocol", 1),
        ByteField("iInterface", 0),
    ]

    def desc(self):
        s = [
            "Interface Descriptor ifnum:%u alt:%u class:%s nep:%u"
            % (
                self.bInterfaceNumber,
                self.bAlternateSetting,
                bInterfaceClass.get(self.bInterfaceClass, str(self.bInterfaceClass)),
                self.bNumEndpoint,
            )
        ]
        return "".join(s)


class bEndpointAddress(USBPacket):
    fields_desc = [
        BitEnumField("direction", 1, 1, USBDefs.EP.Direction.desc),
        BitField("garbage", 0, 3),
        BitField("endpoint_number", 1, 4),
    ]


class bmAttributes(USBPacket):
    fields_desc = [
        BitField("garbage", 0, 2),
        BitField("behaviour", 0, 2),
        BitField("synchro", 0, 2),
        BitEnumField("transfert", 3, 2, USBDefs.EP.TransferType.desc),
    ]


class EndpointDescriptor(USBDescriptor):
    name = "EndpointDescriptor"

    fields_desc = [
        ByteField("bLength", 7),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.ENDPOINT_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        PacketField("bEndpointAddress", bEndpointAddress(), bEndpointAddress),
        PacketField("bmAttributes", bmAttributes(), bmAttributes),
        LEShortField("wMaxPacketSize", 8),
        ByteField("bInterval", 10),
        StrLenField("garbage", "", length_from=lambda p: p.bLength - 7),
    ]

    def desc(self):
        return "Endpoint Descriptor EP%u%s %s int:%u pkt:%u len:%u" % (
            self.bEndpointAddress.endpoint_number,
            USBDefs.EP.Direction[self.bEndpointAddress.direction].ljust(3, " "),
            USBDefs.EP.TransferType[self.bmAttributes.transfert],
            self.bInterval,
            self.wMaxPacketSize,
            self.bLength,
        )


class BOSDescriptor(USBDescriptor):
    fields_desc = [
        FieldLenField(
            "bLength",
            None,
            length_of="bDevCapabilityData",
            fmt="B",
            adjust=lambda pkt, x: x + 3,
        ),
        ByteEnumField(
            "bDescriptorType",
            USBDefs.DescriptorType.BOS_DESCRIPTOR,
            USBDefs.DescriptorType.desc,
        ),
        ByteField("bDevCapabilityType", 0),
        StrLenField("bDevCapabilityData", "", length_from=lambda p: p.bLength - 3),
    ]
