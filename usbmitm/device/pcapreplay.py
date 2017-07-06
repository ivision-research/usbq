#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  PcapInjecter
"""

import sys
import time
import itertools
from threading import Event,Lock
from collections import defaultdict
from Queue import Queue

try:
    import argparse
except:
    print "python-argparse is needed"
    sys.exit(1)

from usbmitm.device.device import USBDevice
from usbmitm.dissect.usbpcap import *
from usbmitm.lib.identity import DeviceIdentity
from usbmitm.dissect.usb import IN,OUT,CTRL
from usbmitm.dissect.usbmitm_proto import *

from scapy.utils import rdpcap
from scapy.config import conf

conf.l2types.register(220,USBPcap)


class PcapReplay(USBDevice):
    _desc_ = "USB Pcap Replayer"

    @classmethod
    def create_arg_subparser(cls,parser):
        parser.add_argument("-p","--pcap",metavar="PCAP_FILE",required=True,help="Pcap file to load")
        parser.add_argument("-s","--start",metavar="INTEGER",default=0,type=int,help="Packet to start")
        parser.add_argument("-n","--nb-packets",metavar="INTEGER",default=0,type=int,help="Nb packets to inject (0 for all)")
        parser.add_argument("--speed",metavar="SPEED",default=HIGH_SPEED,type=int,help="Speed of device (default HIGH_SPEED")

    def __init__(self,args):
        self.pcap = args.pcap
        ident = self.load_identity(args.pcap,args.speed)
        super(PcapReplay,self).__init__(args,ident)
        self.start = args.start
        self.nb = args.nb_packets
        self.consumed = Event()
        self.pkt_sync = Event()
        self.pkt_lock = Lock()
        self.pkt_received = Queue(1)

    def wait_for_consume(self):
        self.consumed.wait()

    def consume(self):
        self.consumed.set()

    def pkt_reception(self,pkt):
        self.pkt_received.put(pkt)

    def wait_for_pkt(self):
        print "wait for pkt"
        return self.pkt_received.get()

    def match(self,pkt):
        """ Return True if pkt match the current replay communication (in case there are several USB communications) """
        return True

    def has_to_handle_pkt(self,pkt):
        """ Return True if pkt needs to be handled """
        return (pkt.is_ctrl_request() or pkt.is_ctrl_response() or
                (pkt.urb_type == SUBMIT and pkt.endpoint_direction == OUT) or
                (pkt.urb_type == COMPLETE and pkt.endpoint_direction == IN))

    def load_identity(self,pcap,speed):
        """ Parse PCAP to find descriptors exchanged and return device identity """
        self.descs = defaultdict(list)
        desc = None
        index = None

        self.num_pkt = 0
        self.pkt_set_conf = None

        for pkt in rdpcap(pcap):
            self.num_pkt += 1
            if not self.match(pkt):
                continue

            if pkt.is_ctrl_request():
                desc = index = None
                urb = pkt.urb_setup.bmRequestType
                if urb.direction == 1 and urb.type == 0 and pkt.urb_setup.bDescriptorType in (1,2,3):
                    desc = pkt.urb_setup.bDescriptorType
                    index = pkt.urb_setup.descriptor_index
                elif pkt.urb_setup.bRequest == 9 and not self.pkt_set_conf:
                    self.pkt_set_conf = self.num_pkt
            elif pkt.is_ctrl_response():
                if desc is None or index is None:
                    continue

                if len(self.descs[desc]) < index+1:
                    self.descs[desc].extend((index-len(self.descs[desc]))*[(None,0)])
                    self.descs[desc].insert(index,(pkt.descriptor,pkt.urb_length))
                else:
                    if pkt.urb_length > self.descs[desc][index][1]:
                        self.descs[desc][index] = (pkt.descriptor,pkt.urb_length)

        descs = {}
        for key,value in self.descs.iteritems():
            descs[key] = map(lambda x:x[0],self.descs[key])

        # for key,value in descs.iteritems():
        #     print "%u" % (key,)
        #     for v in value:
        #         print "\t%r len:%u" % (str(v).encode("hex"),len(str(v)))


        return DeviceIdentity(descs,speed)

    def is_enumeration_request(self,msg):
        if type(msg) is USBPcap:
            return msg.is_ctrl_request()
        return msg.ep.is_ctrl_0() and hasattr(msg.request,"bDescriptorType") and msg.request.bDescriptorType in self.descs

    def is_enumeration_response(self,msg):
        if type(msg) is USBPcap:
            return msg.is_ctrl_response()
        return msg.ep.is_ctrl_0() and hasattr(msg.response,"bDescriptorType") and msg.response.bDescriptorType in self.descs

    def recv_data_usb(self,msg):
        self.recv_usb_device(msg)

    def recv_ctrl0in_data(self,msg):
        self.recv_usb_device(msg)

    def recv_ctrl0out_data(self,msg):
        self.recv_usb_device(msg)

    def recv_usb_device(self,msg):
        self.pkt_reception(msg)

    def same_pkt(self,pcap_pkt,pkt_received):
        """ Compare a USB pkt received with the one contained in the pcap """
        return str(pkt_received.request)[:8] == str(pcap_pkt.urb_setup)[:8]

    def send_pcap_pkt(self,ep,req=None,resp=None,data=""):
        """ Send the USB pcap pkt """
        msg = USBMessageResponse(ep=ep,request=req,response=resp,data=data)
        msg.show()
        self.send_in_data(msg)
        time.sleep(0.2)

    def will_be_received_pkt(self,pkt):
        return pkt.is_ctrl_request()

    def run(self):
        # Do Enumeration
        self.init()

        pkts = rdpcap(self.pcap)

        pkt_num = self.pkt_set_conf+1

        while pkt_num < len(pkts):
            pkt = pkts[pkt_num]
            #print "### READ %r\n" % (pkt,)

            # Check if the packet has to be handled
            if not self.match(pkt) or not self.has_to_handle_pkt(pkt):
                pkt_num += 1
                continue

            # Check if the packet will be received, or if it is just a packet to send
            if self.will_be_received_pkt(pkt):
                if self.is_enumeration_request(pkt):
                    if not self.is_handle(pkt.urb_setup):
                        pkt_received = self.wait_for_pkt()

                        print "Looking for %r" % (pkt_received,)

                        for i in xrange(pkt_num,len(pkts)):
                            if self.same_pkt(pkts[i],pkt_received):
                                print "Found in %u" % (i,)
                                if pkt.endpoint_direction == IN:
                                    for j in xrange(i+1,len(pkts)):
                                        if self.is_enumeration_response(pkts[j]):
                                            npkt = pkts[j]
                                            print "Response in %u" % (j,)
                                            ep = USBEp(epnum=npkt.endpoint_number,eptype=pcaptype_to_eptype[npkt.urb_transfert],epdir=PROTO_IN if npkt.endpoint_direction==IN else PROTO_OUT)
                                            if npkt.urb_status == 0:
                                                self.send_pcap_pkt(ep,req=pkt.urb_setup,resp=npkt.descriptor,data=npkt.data)
                                            else:
                                                self.send_ack(ep,-32)
                                                print "Packet error so not sending data"
                                            break
                                        else:
                                            print "Not resp %u" % (j,)
                                    else:
                                        print "Do not know what is the next pkt %r" % (pkts[i],)
                                        self.disconnect()
                                        sys.exit(0)
                                pkt_num = i
                                break
                            else:
                                print "%u" % (i,)
                        else:
                            print "Not found pkt %r" % (pkt_received,)
                            self.disconnect()
                            sys.exit(0)
                    else: # Identity will handle the response
                        print "Identity handling pkt"
                else:
                    print "Not enumeration: %r" % pkt
            else:
                if self.is_enumeration_response(pkt):
                    print "Response should have already been handled"
                else:
                    print "REPLAY"
                    ep = USBEp(epnum=pkt.endpoint_number,eptype=pcaptype_to_eptype[pkt.urb_transfert],epdir=PROTO_IN if pkt.endpoint_direction==IN else PROTO_OUT)
                    self.send_pcap_pkt(ep,data=pkt.data)
            pkt_num += 1


if __name__ == "__main__":
    parser = PcapReplay.create_arg_parser()
    args = parser.parse_args()
    pcap = PcapReplay(args)
    pcap.run()
    pcap.disconnect()
