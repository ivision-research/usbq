#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  UDP communication

"""

import socket
import select
from usbmitm.usbinterceptor import USBTermination

class USBSocket(USBTermination):
    def __init__(self,args,device):
        USBTermination.__init__(self,args,device)
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.connected = False
        self.dst = None

    def __getattr__(self,attr):
        return getattr(self.sock,attr)

    def read(self):
        data,self.dst = self.sock.recvfrom(4096)
        return data

    def write(self,data):
        if self.dst is None:
            print "Unable to send, not connected"
            return
        return self.sock.sendto(data,self.dst)

    def is_data_ready(self):
        while True:
            (read,write,error) = select.select([self.sock],[],[self.sock],10)
            if error:
                continue
            elif read:
                return True

    def wait_for_data(self,timeout=10):
        (read,write,error) = select.select([self.sock],[],[self.sock],timeout)
        if error:
            return False
        elif read:
            return True


class USBSocketDevice(USBSocket):
    @classmethod
    def create_arg_parser(cls,parser):
        p = parser.add_argument_group("UDP Receiver Options")
        p.add_argument("-b","--bind",metavar="IP",default="0.0.0.0",help="Address to bind to")
        p.add_argument("-p","--port",metavar="PORT",default=64240,type=int,help="Port to bind to")

    def __init__(self,args):
        USBSocket.__init__(self,args,True)
        self.ip = self.args.bind
        self.port = self.args.port
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.sock.bind((self.ip,self.port))


class USBSocketHost(USBSocket):
    @classmethod
    def create_arg_parser(cls,parser):
        p = parser.add_argument_group("UDP Sender Options")
        p.add_argument("--server-ip",default="127.0.0.1",metavar="IP",help="IP Server to connect to")
        p.add_argument("--server-port",default=64241,metavar="PORT",type=int,help="Port Server to connect to")

    def __init__(self,args):
        USBSocket.__init__(self,args,False)
        self.dst = (self.args.server_ip,self.args.server_port)
