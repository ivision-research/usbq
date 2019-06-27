#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.fields import (
    ConditionalField,
    EnumField,
    LEIntField,
    LEShortField,
    LESignedIntField,
    PacketField,
    StrField,
    struct,
)
from scapy.packet import Packet

from .defs import USBDefs
from .dissect.fields import TypePacketField
from .dissect.usb import (
    URB,
    ConfigurationDescriptor,
    Descriptor,
    DeviceDescriptor,
    GetDescriptor,
)

__all__ = [
    'USBMessageHost',
    'USBMessageDevice',
    'ManagementMessage',
    'ManagementReset',
    'ManagementNewDevice',
    'ManagementReload',
    'USBMessageRequest',
    'USBMessageResponse',
    'USBAck',
    'RESET',
    'NEW_DEVICE',
    'RELOAD',
    'PROTO_IN',
    'PROTO_OUT',
]

PROTO_IN = 0
PROTO_OUT = 1

RESET = 0
NEW_DEVICE = 1
RELOAD = 2

mitm_type = {0: "USB", 1: "ACK", 2: "MANAGEMENT"}
management_type = {RESET: "RESET", NEW_DEVICE: "NEW DEVICE", RELOAD: "RELOAD"}
usbmessage_urb_type = {0: "CONTROL", 1: "ISOCHRONOUS", 2: "BULK", 3: "INTERRUPT"}
usbmessage_urb_dir = {PROTO_IN: "IN", PROTO_OUT: "OUT"}
usb_speed = {1: "LOW SPEED", 2: "FULL SPEED", 3: "HIGH SPEED"}


class USBMitm(Packet):
    def desc(self):
        return "%r" % (self,)


class USBEp(USBMitm):
    fields_desc = [
        LEShortField("epnum", 0),
        EnumField("eptype", USBDefs.EP.TransferType.CTRL, usbmessage_urb_type, "<I"),
        EnumField("epdir", PROTO_IN, usbmessage_urb_dir, "<I"),
    ]

    def extract_padding(self, s):
        return "", s

    def is_ctrl_0(self):
        return self.epnum == 0 and self.eptype == USBDefs.EP.TransferType.CTRL

    def is_interrupt(self):
        return self.eptype == USBDefs.EP.TransferType.INT


class USBAck(USBMitm):
    fields_desc = [
        PacketField("ep", USBEp(), USBEp),
        LESignedIntField("status", 0),
        StrField("data", ""),
    ]

    def desc(self):
        return "ACK %r" % (self.status,)


class USBMessageRequest(USBMitm):
    fields_desc = [
        PacketField("ep", USBEp(), USBEp),
        ConditionalField(
            PacketField("request", GetDescriptor(), URB), lambda p: p.ep.is_ctrl_0()
        ),
        StrField("data", ""),
    ]

    def get_usb_payload(self):
        if self.ep.is_ctrl_0():
            return self.request
        return self.data

    def desc(self):
        s = []
        if self.ep.is_ctrl_0():
            s.append(self.request.desc())
        if len(self.data) > 0:
            s.append("+data (len:%u)" % (len(self.data)))
        return " ".join(s)


class USBMessageResponse(USBMitm):
    fields_desc = [
        PacketField("ep", USBEp(), USBEp),
        ConditionalField(
            PacketField("request", GetDescriptor(), URB), lambda p: p.ep.is_ctrl_0()
        ),
        ConditionalField(
            PacketField("response", DeviceDescriptor(), Descriptor),
            lambda p: p.ep.is_ctrl_0() and type(p.request) is GetDescriptor,
        ),
        StrField("data", ""),
    ]

    def get_usb_payload(self):
        if self.ep.is_ctrl_0() and type(self.request) is GetDescriptor:
            return self.response
        return self.data

    def desc(self):
        s = []
        if self.ep.is_ctrl_0() and type(self.request) is GetDescriptor:
            return self.response.desc()
        if len(self.data) > 0:
            s.append("+data (len:%u)" % (len(self.data)))
        return " ".join(s)


class ManagementNewDevice(USBMitm):
    fields_desc = [
        EnumField("speed", 3, usb_speed, "<I"),
        PacketField("device", DeviceDescriptor(), DeviceDescriptor),
        PacketField(
            "configuration", ConfigurationDescriptor(), ConfigurationDescriptor
        ),
    ]

    def desc(self):
        return "NewDevice"


class ManagementReset(USBMitm):
    def desc(self):
        return "Reset"


class ManagementReload(USBMitm):
    def desc(self):
        return "Reload"


class ManagementMessage(USBMitm):
    'USBQ management message'

    fields_desc = [
        EnumField("management_type", None, management_type, "<I"),
        TypePacketField(
            "management_content",
            ManagementReset(),
            "management_type",
            {
                RESET: ManagementReset,
                NEW_DEVICE: ManagementNewDevice,
                RELOAD: ManagementReload,
            },
        ),
    ]  # FIXME: ManagementReset is empty, so if there is nothing to dissect, management_content will be the default value

    def post_build(self, p, pay):
        if self.management_type is None:
            if isinstance(self.management_content, ManagementNewDevice):
                p = struct.pack("<H", NEW_DEVICE) + p[2:]
            elif isinstance(self.management_content, ManagementReload):
                p = struct.pack("<H", RELOAD) + p[2:]
            else:
                p = struct.pack("<H", RESET) + p[2:]
        return p + pay

    def desc(self):
        if self.management_type == RESET:
            return "Reset"
        elif self.management_type == RELOAD:
            return "Reload"
        else:
            return self.management_content.desc()


class USBMessage(USBMitm):
    def is_management(self):
        return self.type == 2

    def is_ack(self):
        return self.type == 1

    def is_usb_data(self):
        return self.type == 0

    def post_build(self, p, pay):
        if self.len is None:
            p = struct.pack("<I", len(p)) + p[4:]
        return p + pay

    def get_usb_payload(self):
        return self.content.get_usb_payload()


class USBMessageDevice(USBMessage):
    'UDP packet payload from ubq_core bearing USB traffic from device->host.'

    name = "USBMessageDevice"
    fields_desc = [
        LEIntField("len", None),
        EnumField("type", 0, mitm_type, "<I"),
        TypePacketField(
            "content",
            ManagementMessage(),
            "type",
            {0: USBMessageResponse, 1: USBAck, 2: ManagementMessage},
        ),
    ]

    def desc(self):
        return self.content.desc()


class USBMessageHost(USBMessage):
    'UDP packet payload from ubq_core bearing USB traffic from host->device.'

    name = "USBMessageHost"
    fields_desc = [
        LEIntField("len", None),
        EnumField("type", 0, mitm_type, "<I"),
        TypePacketField(
            "content",
            ManagementMessage(),
            "type",
            {0: USBMessageRequest, 1: USBAck, 2: ManagementMessage},
        ),
    ]

    def desc(self):
        return self.content.desc()
