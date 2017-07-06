#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  Receiver
"""

import sys
import struct

try:
    import argparse
except:
    print "python-argparse is needed"
    sys.exit(1)

from threading import Thread
import time

from usbinterceptor import USBInterceptor,LinkCommunication
from comm.udp import USBSocketDevice,USBSocketHost
from dissect.usbmitm_proto import *

class USBThread(Thread):
    def __init__(self,termination,hook):
        Thread.__init__(self)
        self.termination = termination
        self.hook = hook
        self.stop = False
        self.daemon = True

    def run(self):
        while not self.stop:
            if self.termination.is_data_ready():
                data = self.termination.read()
                self.hook(data)

class Injecter(USBInterceptor):
    _desc_ = "Simulate Device USB"
    DEVICE = None
    HOST = USBSocketHost

    def __init__(self,args,identity_pkt):
        super(Injecter,self).__init__(args)
        self.identity_pkt = identity_pkt
        self.speed = identity_pkt.speed

    def raw_send(self,data):
        return self.host.write(str(data))

    def send_mitm(self,data):
        msg = USBMessageDevice(type=2,content=ManagementMessage(management_content=data))
        self.raw_send(msg)

    def send_usb(self,data):
        msg = USBMessageDevice(type=0,content=data)
        self.raw_send(msg)

    def send_ack(self,ep,status):
        msg = USBMessageDevice(type=1,content=USBAck(ep=ep,status=status))
        self.raw_send(msg)

    def recv(self,data):
        """ Function called a message is received from Host """
        msg = USBMessageHost(data)
        if msg.type == 0: # Data
            self.recv_usb(msg.content)
        elif msg.type == 1: # ACK
            self.recv_ack(msg.content)
        elif msg.type == 2: # Management
            self.recv_management(msg.content)

    def recv_usb(self,msg):
        pass

    def recv_ack(self,msg):
        pass

    def recv_management(self,msg):
        pass

    def connect(self):
        self.send_mitm(self.identity_pkt)

    def disconnect(self):
        self.send_mitm(ManagementReset())

    def init(self):
        self.thread = USBThread(self.host,self.onReceiveHost)
        self.thread.start()
        self.connect()

    def onReceiveHost(self,data):
        return self.recv(data)


class Receiver(USBInterceptor):
    _desc_ = "Simulate Host USB"
    DEVICE = USBSocketDevice
    HOST = None

    def raw_send(self,data):
        self.device.write(str(data))

    def send_usb(self,data):
        msg = USBMessageHost(type=0,content=data)
        self.raw_send(msg)

    def recv(self,data):
        """ Function called a message is received from Device """
        msg = USBMessageDevice(data)
        if msg.type == 0: # Data
            self.recv_usb(msg.content)
        elif msg.type == 1: # ACK
            self.recv_ack(msg.content)
        elif msg.type == 2: # Management
            self.recv_management(msg.content)

    def recv_usb(self,msg):
        pass

    def recv_ack(self,msg):
        pass

    def recv_management(self,msg):
        pass

    def run(self):
        self.init()
        while not self.shall_stop():
            time.sleep(2)

    def init(self):
        self.thread = USBThread(self.device,self.onReceiveDevice)
        self.thread.start()

    def onReceiveDevice(self,data):
        self.recv(data)

    def shall_stop(self):
        return False


class Forwarder(USBInterceptor):
    _desc_ = "Forward between Host and Device USB"
    DEVICE = USBSocketDevice
    HOST = USBSocketHost

    def __init__(self,args):

        class ForwardTermination(Thread):
            def __init__(self,termination,hook):
                Thread.__init__(self)
                self.termination = termination
                self.hook = hook
                self.stop = False
                self.daemon = True

            def run(self):
                while not self.stop:
                    if self.termination.is_data_ready():
                        data = self.termination.read()
                        self.hook(data)

        USBInterceptor.__init__(self,args)
        self.device_thread = ForwardTermination(self.device,self.onReceiveDevice)
        self.host_thread = ForwardTermination(self.host,self.onReceiveHost)
        self.device_thread.start()
        self.host_thread.start()

    def send_host_mitm(self,data):
        msg = USBMessageDevice(type=2,content=ManagementMessage(management_content=data))
        self.raw_send_host(msg)

    def send_device_mitm(self,data):
        msg = USBMessageHost(type=2,content=ManagementMessage(management_content=data))
        self.raw_send_device(msg)

    def raw_send_host(self,data):
        self.host.write(str(data))

    def raw_send_device(self,data):
        self.device.write(str(data))

    def reset_to_host(self):
        """ Send a RESET packet to the host """
        self.send_host_mitm(ManagementReset())

    def reset_to_device(self):
        """ Send a RESET packet to the device """
        self.send_device_mitm(ManagementReset())

    def reload_to_device(self):
        """ Send a RELOAD packet to the device """
        self.send_device_mitm(ManagementReload())

    def onReceiveDevice(self,data):
        data = self.hookDevice(data)
        if data is not None:
            self.host.write(data)

    def onReceiveHost(self,data):
        data = self.hookHost(data)
        if data is not None:
            self.device.write(data)

    def hookHost(self,data):
        return data

    def hookDevice(self,data):
        return data

    def run(self):
        try:
            while True:
                time.sleep(2)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":

    c = LinkCommunication(Forwarder,USBSocketDevice,USBSocketHost)
    #c = LinkCommunication(Receiver,USBSocketDevice,None)
    #print c.__dict__
    parser = c.create_arg_parser()
    args = parser.parse_args()
    x = c(args)
    x.run()
