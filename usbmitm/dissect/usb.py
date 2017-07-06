#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.fields import *
from scapy.packet import Packet

from fields import *

# Endpoint Type
CTRL = 0
ISOC = 1
BULK = 2
INT  = 3

# Endpoint Direction
OUT = 0
IN  = 1

# SPEED
LOW_SPEED  = 1
FULL_SPEED = 2
HIGH_SPEED = 3

# DESCRIPTOR TYPE
DEVICE_DESCRIPTOR        = 1
CONFIGURATION_DESCRIPTOR = 2
STRING_DESCRIPTOR        = 3
INTERFACE_DESCRIPTOR     = 4
ENDPOINT_DESCRIPTOR      = 5
BOS_DESCRIPTOR           = 0xf
HID_DESCRIPTOR           = 0x21
HID_REPORT_DESCRIPTOR    = 0x22

# CLASS
HID          = 3
MASS_STORAGE = 8

urb_direction = {0:"host-to-device",1:"device-to-host"}
urb_type = {0:"standard"}
urb_recipient = {0:"device"}
urb_bRequest = {1:"GET REPORT",6:"GET DESCRIPTOR",9:"SET CONFIGURATION",0xa:"SET IDLE",0xb:"SET INTERFACE"}
urb_bDescriptorType = {DEVICE_DESCRIPTOR:"device",CONFIGURATION_DESCRIPTOR:"configuration",STRING_DESCRIPTOR:"string",INTERFACE_DESCRIPTOR:"interface",ENDPOINT_DESCRIPTOR:"endpoint",BOS_DESCRIPTOR:"bos",HID_DESCRIPTOR:"HID",HID_REPORT_DESCRIPTOR:"HID REPORT"}
urb_language = {0:"no language specified"}

class USBPacket(Packet):
    def extract_padding(self,s):
        return "",s

    def desc(self):
        return "%s" % (self.__class__.__name__,)

class USBDescriptor(USBPacket):
    def post_build(self,p,pay):
        if self.bLength is None:
            p = struct.pack("B",len(p)) + p[1:]
        return p+pay

    def pre_dissect(self,s):
        self.desc_len = len(s)
        return s

    def post_build(self,pkt,pay):
        if hasattr(self,"desc_len"):
            return (pkt+pay)[:self.desc_len]
        else:
            return pkt+pay

class bmRequestType(USBPacket):
    fields_desc = [
        BitEnumField("direction",1,1,urb_direction),
        BitEnumField("type",0,2,urb_type),
        BitEnumField("recipient",0,5,urb_recipient),
    ]

class RequestDescriptor(USBPacket):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(),bmRequestType),
        ByteField("bRequest",0),
        LEShortField("wValue",1),
        LEShortField("wIndex",0),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "REQ:%u val:%u ind:%u len:%u" % (self.bRequest,self.wValue,self.wIndex,self.wLength)

class GetDescriptor(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(),bmRequestType),
        ByteEnumField("bRequest",6,urb_bRequest),
        ByteField("descriptor_index",0),
        ByteEnumField("bDescriptorType",1,urb_bDescriptorType),
        ShortEnumField("language_id",0,urb_language),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "GetDescriptor %s [sz:%u]" % (urb_bDescriptorType.get(self.bDescriptorType,"ukn"),self.wLength)

class GetReport(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(direction=1,type=1,recipient=1),bmRequestType),
        ByteEnumField("bRequest",1,urb_bRequest),
        LEShortField("wValue",0),
        LEShortField("wIndex",0),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "GetReport"


class SetConfiguration(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(direction=0),bmRequestType),
        ByteEnumField("bRequest",9,urb_bRequest),
        ByteField("bConfigurationValue",1),
        LEShortField("wIndex",0),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "SetConfiguration %u" % (self.bConfigurationValue,)


class SetInterface(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(direction=0,type=0,recipient=1),bmRequestType),
        ByteEnumField("bRequest",11,urb_bRequest),
        LEShortField("bAlternateSetting",0), # In fact byte + 1 padding
        LEShortField("wInterface",1),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "SetInterface intf:%u alt:%u" % (self.wInterface,self.bAlternateSetting)


class SetIDLE(RequestDescriptor):
    fields_desc = [
        PacketField("bmRequestType",bmRequestType(),bmRequestType),
        ByteEnumField("bRequest",0xa,urb_bRequest),
        LEShortField("wValue",1),
        LEShortField("wIndex",0),
        LEShortField("wLength",0),
    ]

    def desc(self):
        return "SetIDLE"

def URB(payload):
    breqtype = ord(payload[0])
    breq = ord(payload[1])
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


bDeviceClass = {0:"Device"}
bDeviceProtocol = {0:"See Interface"}
idVendor = {}
idProduct = {}

def Descriptor(payload):
    from hid import HIDDescriptor,HIDReportDescriptor
    if len(payload) < 2:
        return RawDescriptor(payload)
    desctype = ord(payload[1])
    if desctype == 1:
        l = ord(payload[0])
        if l == 5:
            cls = HIDReportDescriptor
        elif len(payload) != 18:
            cls = RawDescriptor(payload)
        else:
            cls = DeviceDescriptor
    elif desctype == CONFIGURATION_DESCRIPTOR:
        cls = ConfigurationDescriptor
    elif desctype == STRING_DESCRIPTOR:
        cls = StringDescriptor
    elif desctype == INTERFACE_DESCRIPTOR:
        cls = InterfaceDescriptor
    elif desctype == ENDPOINT_DESCRIPTOR:
        cls = EndpointDescriptor
    elif desctype == BOS_DESCRIPTOR:
        cls = BOSDescriptor
    elif desctype == HID_DESCRIPTOR:
        cls = HIDDescriptor
    else:
        cls = UnknownDescriptor
    return cls(payload)


class RawDescriptor(USBDescriptor):
    fields_desc = [
        StrField("raw","")
    ]

class UnknownDescriptor(USBDescriptor):
    fields_desc = [
        ByteField("bLength",None),
        ByteEnumField("bDescriptorType",1,urb_bDescriptorType),
        BytesFixedLenField("data","",length_from=lambda p:p.bLength-2)
    ]


class DeviceDescriptor(USBDescriptor):
    fields_desc = [
        ByteField("bLength",18),
        ByteEnumField("bDescriptorType",DEVICE_DESCRIPTOR,urb_bDescriptorType),
        LEShortField("bcdUSB",0x0200),
        ByteEnumField("bDeviceClass",0,bDeviceClass),
        ByteField("bDeviceSubClass",0),
        ByteEnumField("bDeviceProtocol",0,bDeviceProtocol),
        ByteField("bMaxPacketSize",64),
        XLEShortEnumField("idVendor",0x6464,idVendor),
        XLEShortEnumField("idProduct",0x6464,idProduct),
        LEShortField("bcdDevice",0x0200),
        XByteField("iManufacturer",0),
        XByteField("iProduct",2),
        ByteField("iSerialNumber",0),
        ByteField("bNumConfigurations",1),
    ]

    def desc(self):
        s = ["Device Descriptor vid:%02x pid:%02x maxpkt:%u len:%u" % (self.idVendor,self.idProduct,self.bMaxPacketSize,self.bLength)]
        if self.bNumConfigurations != 1:
            s.append("nconf:%u" % (self.bNumConfigurations,))
        return " ".join(s)

class ConfigurationDescriptor(USBDescriptor):
    name = "ConfigurationDescriptor"

    fields_desc = [
        ByteField("bLength",9),
        ByteEnumField("bDescriptorType",CONFIGURATION_DESCRIPTOR,urb_bDescriptorType),
        LEShortField("wTotalLength",None),
        ByteField("bNumInterfaces",1),
        ByteField("bConfigurationValue",1),
        ByteField("iConfiguration",0),
        ByteField("bmAttributes",0xa0),
        ByteField("bMaxPower",50),
        PacketListField("descriptors",None,Descriptor),
    ]

    def post_build(self,p,pay):
        if self.wTotalLength is None:
            p = p[:2] + struct.pack("<H",len(p)) + p[4:]
        return p+pay

    def desc(self):
        s = ["Configuration Descriptor nintf:%u" % (self.bNumInterfaces,)]
        for d in self.descriptors:
            s.append(d.desc())
        return "\n   ".join(s)


class StringDescriptor(USBDescriptor):
    fields_desc = [
        FieldLenField("bLength",None,length_of="bString",fmt="B",adjust=lambda pkt,x:x+2),
        ByteEnumField("bDescriptorType",STRING_DESCRIPTOR,urb_bDescriptorType),
        #ConditionalField(LEShortField("wLANGID",0x0409),lambda p:p.bLength==4),
        UnicodeStringLenField("bString","\x09\x04",length_from=lambda p:p.bLength-2),
    ]

    def desc(self):
        return "String Descriptor [%s] len:%u" % (self.bString,self.bLength)

bInterfaceClass = {3:"hid",8:"mass_storage"}

class InterfaceDescriptor(USBDescriptor):
    name = "InterfaceDescriptor"

    fields_desc = [
        ByteField("bLength",9),
        ByteEnumField("bDescriptorType",INTERFACE_DESCRIPTOR,urb_bDescriptorType),
        ByteField("bInterfaceNumber",0),
        ByteField("bAlternateSetting",0),
        ByteField("bNumEndpoint",1),
        ByteEnumField("bInterfaceClass",3,bInterfaceClass),
        ByteField("bInterfaceSubClass",1),
        ByteField("bInterfaceProtocol",1),
        ByteField("iInterface",0),
    ]

    def desc(self):
        s = ["Interface Descriptor ifnum:%u alt:%u class:%s nep:%u" % (
            self.bInterfaceNumber,
            self.bAlternateSetting,
            bInterfaceClass.get(self.bInterfaceClass,str(self.bInterfaceClass)),
            self.bNumEndpoint)]
        return "".join(s)

bEndpointDirection = {OUT:"OUT",IN:"IN"}

class bEndpointAddress(USBPacket):
    fields_desc = [
        BitEnumField("direction",1,1,bEndpointDirection),
        BitField("garbage",0,3),
        BitField("endpoint_number",1,4),
    ]

attribute_transfert_type = {
    CTRL:"Control",
    ISOC:"Isochronous",
    BULK:"Bulk",
    INT :"Interrupt"
}

class bmAttributes(USBPacket):
    fields_desc = [
        BitField("garbage",0,2),
        BitField("behaviour",0,2),
        BitField("synchro",0,2),
        BitEnumField("transfert",3,2,attribute_transfert_type),
    ]

class EndpointDescriptor(USBDescriptor):
    name = "EndpointDescriptor"

    fields_desc = [
        ByteField("bLength",7),
        ByteEnumField("bDescriptorType",ENDPOINT_DESCRIPTOR,urb_bDescriptorType),
        PacketField("bEndpointAddress",bEndpointAddress(),bEndpointAddress),
        PacketField("bmAttributes",bmAttributes(),bmAttributes),
        LEShortField("wMaxPacketSize",8),
        ByteField("bInterval",10),
        StrLenField("garbage","",length_from=lambda p:p.bLength-7),
    ]

    def desc(self):
        return "Endpoint Descriptor EP%u%s %s int:%u pkt:%u len:%u" % (
            self.bEndpointAddress.endpoint_number,
            bEndpointDirection[self.bEndpointAddress.direction].ljust(3," "),
            attribute_transfert_type[self.bmAttributes.transfert],
            self.bInterval,self.wMaxPacketSize,self.bLength
        )

class BOSDescriptor(USBDescriptor):
    fields_desc = [
        FieldLenField("bLength",None,length_of="bDevCapabilityData",fmt="B",adjust=lambda pkt,x:x+3),
        ByteEnumField("bDescriptorType",BOS_DESCRIPTOR,urb_bDescriptorType),
        ByteField("bDevCapabilityType",0),
        StrLenField("bDevCapabilityData","",length_from=lambda p:p.bLength-3),
    ]


if __name__ == "__main__":
    data = sys.argv[1].replace(" ","").decode("hex")
    l1 = len(data)
    desc = Descriptor(data)
    desc.show()
    l2 = len(str(desc))
    print "%u:%u" % (l1,l2)
