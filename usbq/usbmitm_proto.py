#!/usr/bin/env python
# -*- coding: utf-8 -*-
from scapy.fields import ConditionalField
from scapy.fields import EnumField
from scapy.fields import LEIntField
from scapy.fields import LEShortField
from scapy.fields import LESignedIntField
from scapy.fields import PacketField
from scapy.fields import StrField
from scapy.fields import struct
from scapy.packet import Packet

from .defs import AutoDescEnum
from .defs import USBDefs
from .dissect.fields import TypePacketField
from .dissect.usb import ConfigurationDescriptor
from .dissect.usb import Descriptor
from .dissect.usb import DeviceDescriptor
from .dissect.usb import GetDescriptor
from .dissect.usb import URB

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
]


class USBMitm(Packet):
    def desc(self):
        return '%r' % (self,)

    class MitmType(AutoDescEnum):
        'USBQ Packet Type'

        # ubq_core/msg.h
        USB = 0
        ACK = 1
        MANAGEMENT = 2

    class ManagementType(AutoDescEnum):
        'USBQ Management Packet Type'

        # ubq_core/msg.h
        RESET = 0
        NEW_DEVICE = 1
        RELOAD = 2

    class USBSpeed(AutoDescEnum):
        'USBQ Device Speed'

        # kernel linux/usb/ch9.h
        LOW_SPEED = 1
        FULL_SPEED = 2
        HIGH_SPEED = 3

    class URBEPDirection(AutoDescEnum):
        '''
        URB EP direction

        From the Linux kernel's perspective the direction of the
        endpoint.
        '''

        # ubq_core/types.h
        URB_IN = 0
        URB_OUT = 1


class USBEp(USBMitm):
    fields_desc = [
        LEShortField('epnum', 0),
        EnumField(
            'eptype', USBDefs.EP.TransferType.CTRL, USBDefs.EP.TransferType.desc, '<I'
        ),
        EnumField('epdir', USBDefs.EP.Direction.IN, USBDefs.EP.Direction.desc, '<I'),
    ]

    def extract_padding(self, s):
        return '', s

    def is_ctrl_0(self):
        return self.epnum == 0 and self.eptype == USBDefs.EP.TransferType.CTRL

    def is_interrupt(self):
        return self.eptype == USBDefs.EP.TransferType.INT


class USBAck(USBMitm):
    fields_desc = [
        PacketField('ep', USBEp(), USBEp),
        LESignedIntField('status', 0),
        StrField('data', ''),
    ]

    def desc(self):
        return 'ACK %r' % (self.status,)


class USBMessageRequest(USBMitm):
    fields_desc = [
        PacketField('ep', USBEp(), USBEp),
        ConditionalField(
            PacketField('request', GetDescriptor(), URB), lambda p: p.ep.is_ctrl_0()
        ),
        StrField('data', ''),
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
            s.append('+data (len:%u)' % (len(self.data)))
        return ' '.join(s)


class USBMessageResponse(USBMitm):
    fields_desc = [
        PacketField('ep', USBEp(), USBEp),
        ConditionalField(
            PacketField('request', GetDescriptor(), URB), lambda p: p.ep.is_ctrl_0()
        ),
        ConditionalField(
            PacketField('response', DeviceDescriptor(), Descriptor),
            lambda p: p.ep.is_ctrl_0() and type(p.request) is GetDescriptor,
        ),
        StrField('data', ''),
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
            s.append('+data (len:%u)' % (len(self.data)))
        return ' '.join(s)


class ManagementNewDevice(USBMitm):
    fields_desc = [
        EnumField('speed', USBMitm.USBSpeed.HIGH_SPEED, USBMitm.USBSpeed.desc, '<I'),
        PacketField('device', DeviceDescriptor(), DeviceDescriptor),
        PacketField(
            'configuration', ConfigurationDescriptor(), ConfigurationDescriptor
        ),
    ]

    def desc(self):
        return 'NewDevice'


class ManagementReset(USBMitm):
    def desc(self):
        return 'Reset'


class ManagementReload(USBMitm):
    def desc(self):
        return 'Reload'


class ManagementMessage(USBMitm):
    'USBQ management message'

    fields_desc = [
        EnumField(
            'management_type',
            USBMitm.ManagementType.RESET,
            USBMitm.ManagementType.desc,
            '<I',
        ),
        TypePacketField(
            'management_content',
            ManagementReset(),
            'management_type',
            {
                USBMitm.ManagementType.RESET: ManagementReset,
                USBMitm.ManagementType.NEW_DEVICE: ManagementNewDevice,
                USBMitm.ManagementType.RELOAD: ManagementReload,
            },
        ),
    ]  # FIXME: ManagementReset is empty, so if there is nothing to dissect, management_content will be the default value

    def post_build(self, p, pay):
        if self.management_type is None:
            if isinstance(self.management_content, ManagementNewDevice):
                p = struct.pack('<H', USBMitm.ManagementType.NEW_DEVICE) + p[2:]
            elif isinstance(self.management_content, ManagementReload):
                p = struct.pack('<H', USBMitm.ManagementType.RELOAD) + p[2:]
            else:
                p = struct.pack('<H', USBMitm.ManagementType.RESET) + p[2:]
        return p + pay

    def desc(self):
        if self.management_type == USBMitm.ManagementType.RESET:
            return 'Reset'
        elif self.management_type == USBMitm.ManagementType.RELOAD:
            return 'Reload'
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
            p = struct.pack('<I', len(p)) + p[4:]
        return p + pay

    def get_usb_payload(self):
        return self.content.get_usb_payload()


class USBMessageDevice(USBMessage):
    'UDP packet payload from ubq_core bearing USB traffic from device->host.'

    name = 'USBMessageDevice'
    fields_desc = [
        LEIntField('len', None),
        EnumField('type', USBMitm.MitmType.USB, USBMitm.MitmType.desc, '<I'),
        TypePacketField(
            'content',
            ManagementMessage(),
            'type',
            {0: USBMessageResponse, 1: USBAck, 2: ManagementMessage},
        ),
    ]

    def desc(self):
        return self.content.desc()


class USBMessageHost(USBMessage):
    'UDP packet payload from ubq_core bearing USB traffic from host->device.'

    name = 'USBMessageHost'
    fields_desc = [
        LEIntField('len', None),
        EnumField(
            'type', USBMitm.ManagementType.RESET, USBMitm.ManagementType.desc, '<I'
        ),
        TypePacketField(
            'content',
            ManagementMessage(),
            'type',
            {0: USBMessageRequest, 1: USBAck, 2: ManagementMessage},
        ),
    ]

    def desc(self):
        return self.content.desc()
