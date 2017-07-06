#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.fields import *

class XLEShortEnumField(LEShortEnumField):
    def i2repr_one(self, pkt, x):
        if self not in conf.noenum and not isinstance(x,VolatileValue) and x in self.i2s:
            return self.i2s[x]
        return lhex(x)

class BytesFixedLenField(StrFixedLenField):
    def i2repr(self, pkt, v):
        return repr(v)

class UnicodeStringLenField(StrLenField):
    def i2repr(self,pkt,v):
        v = v.replace("\x00","")
        return repr(v)

class LESignedIntEnumField(EnumField):
    def __init__(self, name, default, enum):
        EnumField.__init__(self, name, default, enum, "<i")

class TypePacketField(StrField):
    holds_packets=1
    def __init__(self, name, default, type_field, type_pkt, remain=0):
        StrField.__init__(self, name, default,remain=remain)
        self.type_pkt = type_pkt
        self.type_field = type_field
    def i2m(self, pkt, i):
        return str(i)
    def m2i(self, pkt, m):
        t = getattr(pkt,self.type_field)
        return self.type_pkt[t](m)
    def getfield(self, pkt, s):
        i = self.m2i(pkt, s)
        remain = ""
        if 'Padding' in i:
            r = i['Padding']
            del(r.underlayer.payload)
            remain = r.load
        return remain,i
