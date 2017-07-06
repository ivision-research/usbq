#!/usr/bin/env python

from scapy.fields import *
from scapy.packet import Packet

from fields import *

class S1(Packet):
    fields_desc = [
        IntField("X",0)
    ]

class S2(Packet):
    fields_desc = [
        ShortField("X",0),
        ShortField("Y",0)
    ]

type_fields = {
    0:S1,
    1:S2
}

class P1(Packet):
    fields_desc = [
        ByteField("type",0),
        TypePacketField("pkt",S1,"type",type_fields)
    ]

if __name__ == "__main__":
    print "ouin"
    P1("\x00\x00\x00\x00\x00").show()
    P1("\x01\x00\x00\x00\x00").show()
