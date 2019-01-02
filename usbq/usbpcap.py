# -*- coding: utf-8 -*-

__all__ = [
    'USBPcap',
    'usb_to_usbpcap',
    'usbdev_to_usbpcap',
    'usbhost_to_usbpcap',
    'req_from_msg',
    'ack_from_msg',
]

from scapy.fields import *
from scapy.packet import Packet

from .dissect.fields import *
from .dissect.usb import *
from .dissect.defs import *
from .usbmitm_proto import *

SUBMIT = "S"
COMPLETE = "C"

PCAP_CTRL = 2
PCAP_INT = 1
PCAP_BULK = 3
PCAP_ISOC = 4

pcap_urb_type = {COMPLETE: "URB_COMPLETE", SUBMIT: "URB_SUBMIT"}
pcap_urb_transfert = {
    PCAP_INT: "URB_INTERRUPT",
    PCAP_CTRL: "URB_CONTROL",
    PCAP_BULK: "URB_BULK",
    PCAP_ISOC: "URB_ISOC",
}
pcap_urb_status = {0: "Success", -115: "Operation in progress", -32: "Broken Pipe"}
pcap_setup_request = {0: "relevant", 0x2d: "not relevant"}
pcap_data_present = {0: "present", 0x3c: "not present"}

eptype_to_pcap_type = {CTRL: PCAP_CTRL, INT: PCAP_INT, BULK: PCAP_BULK, ISOC: PCAP_ISOC}
pcaptype_to_eptype = {v: k for k, v in list(eptype_to_pcap_type.items())}

pcap_garbage = '\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\x00'


def usb_to_usbpcap(msg):
    pcap = USBPcap()
    pcap.urb_transfert = eptype_to_pcap_type[msg.ep.eptype]
    pcap.endpoint_direction = OUT if msg.ep.epdir == PROTO_OUT else IN
    pcap.endpoint_number = msg.ep.epnum
    pcap.garbage = "\x00" * 24
    return pcap


def usbdev_to_usbpcap(msg):
    """ Transform a USBMessageDevice message to a USBPcap message """
    pcap = usb_to_usbpcap(msg)
    pcap.urb_type = "C"
    pcap.device_setup_request = 0x2d  # No relevant
    pcap.data_present = 0 if msg.ep.eptype == 1 else 0x3e
    if msg.ep.is_ctrl_0() and msg.ep.epdir == PROTO_IN:
        pcap.descriptor = msg.response
        pcap.urb_length = len(msg.response) + len(msg.data)
        pcap.data_length = len(msg.response) + len(msg.data)
    else:
        pcap.descriptor = None
        pcap.urb_length = len(msg.data)
        pcap.data_length = len(msg.data)
    pcap.urb_setup = None
    pcap.data = msg.data
    return pcap


def usbhost_to_usbpcap(msg):
    """ Transform a USBMessageHost message to a USBPcap message """
    pcap = usb_to_usbpcap(msg)
    pcap.urb_type = "S"
    pcap.device_setup_request = 0  # Relevant
    pcap.data_present = 0x3e if msg.ep.eptype == 1 else 0
    if msg.ep.is_ctrl_0() and msg.ep.epdir == PROTO_IN:
        pcap.urb_length = msg.request.wLength
        pcap.data_length = 0
    else:
        pcap.descriptor = None
        pcap.urb_length = len(msg.data)
        pcap.data_length = len(msg.data)
    pcap.urb_setup = msg.request
    pcap.data = msg.data
    return pcap


def req_from_msg(msg):
    """ Find request that has generated msg """
    req = usb_to_usbpcap(msg)
    pcap.urb_type = "S"
    req.status = -115
    req.urb_length = len(msg.data)
    req.data_length = 0
    req.urb_setup = None
    return req


def ack_from_msg(msg):
    """ Find ack for the msg """
    ack = usb_to_usbpcap(msg)
    ack.urb_type = "C"
    if msg.ep.eptype == CTRL and msg.ep.epdir == PROTO_OUT:
        ack.urb_length = msg.request.wLength
    else:
        ack.urb_length = len(msg.data)
    ack.data_length = 0
    ack.urb_setup = None
    return ack


class USBPcap(Packet):
    """ Packet used in pcap files """

    name = "USBPcap"
    fields_desc = [
        LELongField("urb_id", 0),
        CharEnumField("urb_type", SUBMIT, pcap_urb_type),
        ByteEnumField("urb_transfert", PCAP_CTRL, pcap_urb_transfert),
        BitEnumField("endpoint_direction", IN, 1, bEndpointDirection),
        BitField("endpoint_number", 0, 7),
        ByteField("device", 1),
        LEShortField("bus_id", 1),
        ByteEnumField("device_setup_request", 0, pcap_setup_request),
        ByteEnumField("data_present", 0, pcap_data_present),
        LELongField("urb_sec", 0),
        LEIntField("urb_usec", 0),
        LESignedIntEnumField("urb_status", 0, pcap_urb_status),
        LEIntField("urb_length", 0),
        LEIntField("data_length", 0),
        ConditionalField(
            PacketField("urb_setup", GetDescriptor(), URB),
            lambda p: p.urb_transfert == 2 and p.urb_type == "S",
        ),
        # added max(0, ...) unclear why needed
        BytesFixedLenField(
            "garbage",
            pcap_garbage,
            length_from=lambda p: 24
            if p.urb_setup is None
            else max(0, 24 - len(str(p.urb_setup))),
        ),
        ConditionalField(
            PacketField("descriptor", DeviceDescriptor(), Descriptor),
            lambda p: p.urb_transfert == 2 and p.urb_type == "C" and p.data_length > 0,
        ),
        StrField("data", ""),
    ]

    def is_ctrl_request(self):
        return self.urb_type == SUBMIT and self.urb_transfert == PCAP_CTRL

    def is_ctrl_response(self):
        return self.urb_type == COMPLETE and self.urb_transfert == PCAP_CTRL
