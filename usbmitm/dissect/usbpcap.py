#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.fields import *
from scapy.packet import Packet

from fields import *
from usb import *

SUBMIT   = "S"
COMPLETE = "C"

PCAP_CTRL = 2
PCAP_INT  = 1
PCAP_BULK = 3
PCAP_ISOC = 4

pcap_urb_type = {COMPLETE:"URB_COMPLETE",SUBMIT:"URB_SUBMIT"}
pcap_urb_transfert = {PCAP_INT:"URB_INTERRUPT",PCAP_CTRL:"URB_CONTROL",PCAP_BULK:"URB_BULK",PCAP_ISOC:"URB_ISOC"}
pcap_urb_status = {0:"Success",-115:"Operation in progress",-32:"Broken Pipe"}
pcap_setup_request = {0:"relevant",0x2d:"not relevant"}
pcap_data_present = {0:"present",0x3c:"not present"}

eptype_to_pcap_type = {CTRL:PCAP_CTRL,INT:PCAP_INT,BULK:PCAP_BULK,ISOC:PCAP_ISOC}
pcaptype_to_eptype = {v: k for k, v in eptype_to_pcap_type.items()}

pcap_garbage = '\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\x00'


class USBPcap(Packet):
    """ Packet used in pcap files """
    name = "USBPcap"
    fields_desc = [
        LELongField("urb_id",0),
        CharEnumField("urb_type",SUBMIT,pcap_urb_type),
        ByteEnumField("urb_transfert",PCAP_CTRL,pcap_urb_transfert),
        BitEnumField("endpoint_direction",IN,1,bEndpointDirection),
        BitField("endpoint_number",0,7),
        ByteField("device",1),
        LEShortField("bus_id",1),
        ByteEnumField("device_setup_request",0,pcap_setup_request),
        ByteEnumField("data_present",0,pcap_data_present),
        LELongField("urb_sec",0),
        LEIntField("urb_usec",0),
        LESignedIntEnumField("urb_status",0,pcap_urb_status),
        LEIntField("urb_length",0),
        LEIntField("data_length",0),
        ConditionalField(PacketField("urb_setup",GetDescriptor(),URB),lambda p:p.urb_transfert==2 and p.urb_type=="S"),
        BytesFixedLenField("garbage",pcap_garbage,length_from=lambda p:24 if p.urb_setup is None else 24-len(str(p.urb_setup))),
        ConditionalField(PacketField("descriptor",DeviceDescriptor(),Descriptor),lambda p:p.urb_transfert==2 and p.urb_type=="C" and p.data_length > 0),
        StrField("data","")
    ]

    def is_ctrl_request(self):
        return self.urb_type == SUBMIT and self.urb_transfert == PCAP_CTRL

    def is_ctrl_response(self):
        return self.urb_type == COMPLETE and self.urb_transfert == PCAP_CTRL

if __name__ == "__main__":
    import sys
    from scapy.utils import rdpcap
    from scapy.config import conf

    conf.l2types.register(220,USBPcap)
    pkts = rdpcap(sys.argv[1])
    for pkt in pkts:
        pkt.show()
