#!/usr/bin/env python

from threading import Event
from collections import defaultdict
import time

from device import USBDevice
from usbmitm.comm.udp import USBSocketDevice,USBSocketHost
from usbmitm.usbinterceptor import USBInterceptor
from usbmitm.device.keyboard import Keyboard

from usbmitm.lib.identity import DeviceIdentity
from usbmitm.lib.interface import Interface
from usbmitm.lib.endpoint import Endpoint
from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.dissect.hid import *
from usbmitm.device.keyboard import KeyboardInterface

# class _DeviceScan(object):
#     def __init__(self):
#         self.response = Event()
#         self.timeout = 5.0

#     def is_handled(self):
#         self.init()
#         self.communicate()
#         res = self.response.wait(self.timeout)
#         self.disconnect()
#         return res

#     def communicate(self):
#         pass

# class DeviceScan(USBDevice):
#     def __init__(self,args,identity):
#         super(DeviceScan,self).__init__(args,identity)
#         self.response = Event()
#         self.timeout = 5.0
#         self.epin = []
#         for desc in identity[2][0].descriptors:
#             if type(desc) is EndpointDescriptor and desc.bEndpointAddress.direction == 1:
#                 addr = desc.bEndpointAddress
#                 ep = USBEp(epnum=addr.endpoint_number,eptype=desc.bmAttributes.transfert,epdir=0)
#                 print addr.direction
#                 ep.show()
#                 self.epin.append(ep)


#     def is_handled(self):
#         self.init()
#         self.communicate()
#         res = self.response.wait(self.timeout)
#         self.disconnect()
#         return res

#     def communicate(self):
#         pass
#         # for ep in self.epin:
#         #     self.send_in_data(USBMessageResponse(ep=ep,data=""))

#     def recv_data_usb(self,msg):
#         print "recv"



# class KeyboardScan(Keyboard,_DeviceScan):
#     def __init__(self,args):
#         _DeviceScan.__init__(self)
#         Keyboard.__init__(self,args)

#     def communicate(self):
#         self.send_event("")

#     def recv_ack(self,msg):
#         if self.configured:
#             self.response.set()

# class MassStorageScan(USBDevice,_DeviceScan):
#     def __init__(self,args):
#         _DeviceScan.__init__(self)
#         identity = DeviceIdentity([DeviceDescriptor(),
#                                    ConfigurationDescriptor(descriptors=[
#                                        InterfaceDescriptor(bInterfaceClass=8,bInterfaceSubClass=6,bInterfaceProtocol=80,bNumEndpoint=2),
#                                        EP("bulk","out",1,512),
#                                        EP("bulk","in",1,512)]),
#                                    StringDescriptor(),
#                                    StringDescriptor(bString="CBM    ".encode('utf-16le')),
#                                    StringDescriptor(bString="Flash Disk      ".encode('utf-16le')),]
#                               )
#         USBDevice.__init__(self,args,identity)

#     def recv_ctrl0in(self,msg):
#         if not self.configured:
#             return super(MassStorageScan,self).recv_ctrl0in(msg)
#         else:
#             self.response.set()

# def EP(typ,direction,number,pkts=64,interval=0):
#     htyp = {"bulk":2,"interrupt":3,"isoc":1}
#     hdir = {"out":0,"in":1}
#     addr = bEndpointAddress(direction=hdir[direction],endpoint_number=number)
#     attr = bmAttributes(transfert=htyp[typ])
#     return EndpointDescriptor(bEndpointAddress=addr,bmAttributes=attr,wMaxPacketSize=pkts,bInterval=interval)


class USBDeviceScan(USBDevice):
    def __init__(self,args,name,interface,epin=None):
        ident = DeviceIdentity.from_interface(interface)
        super(USBDeviceScan,self).__init__(args,ident)
        self.name = name
        self.response = Event()
        self.timeout = 5.0
        self.epin = epin

    def is_handled(self):
        self.init()
        self.communicate()
        res = self.response.wait(self.timeout)
        self.disconnect()
        return res

    def communicate(self):
        if self.epin:
            self.send_usb(USBMessageResponse(ep=self.epin,data=""))

    def recv_ack(self,msg):
        if self.configured and self.epin:
            self.response.set()

    def recv_usb(self,msg):
        if self.configured and not self.epin:
            if hasattr(msg,"request") and type(msg.request) is not SetIDLE:
                self.response.set()
                return
        super(USBDeviceScan,self).recv_usb(msg)


MassStorageInterface = Interface(descriptors=[Endpoint(1,BULK,IN,512),Endpoint(1,BULK,OUT,512)],cls=8,subcls=6,proto=80)
PrinterInterface = Interface(descriptors=[Endpoint(1,BULK,IN,64),Endpoint(1,BULK,OUT,64)],cls=7,subcls=1,proto=2)

DEVICES = [
    # KeyboardScan,
    # MassStorageScan
    {"name":"Keyboard","interface":KeyboardInterface},
    {"name":"Mass-Storage","interface":MassStorageInterface},
    {"name":"Printer","interface":MassStorageInterface},
]

class USBScan(USBInterceptor):
    """ Scan accepted devices """
    DEVICE = None
    HOST = USBSocketHost

    # def run(self):
    #     for device in DEVICES:
    #         if type(device) is list:
    #             s = device[0]
    #             device = DeviceScan(self.args,device[1])
    #         else:
    #             device = device(self.args)
    #             s = device.__class__.__name__
    #         if device.is_handled():
    #             print "%s handled" % (s,)
    #         else:
    #             print "%s not handled" % (s,)

    def run(self):
        for param in DEVICES:
            param["args"] = self.args
            device = USBDeviceScan(**param)
            if device.is_handled():
                print "%s handled" % (device.name,)
            else:
                print "%s not handled" % (device.name,)

    # def __init__(self,args):
    #     identity_pkt = ManagementNewDevice(speed=3,device=DeviceDescriptor(),configuration=ConfigurationDescriptor())
    #     super(USBScan,self).__init__(args,identity_pkt)
    #     self.ep0 = USBEp(epnum=0,eptype=0,epdir=0)
    #     self.timeout = 15

    # def recv(self):
    #     if not self.host.wait_for_data(self.timeout):
    #         return None
    #     return self.host.read()

    # def start_communication(self,identity):
    #     """ Run a fuzz test session """
    #     self.connect()
    #     while True:
    #         msg = self.recv()

    #         msg = USBMessageHost(msg)

    #         # Ignore non USB messages
    #         if msg.type != 0:
    #             continue

    #         msg = msg.content

    #         # Ignore non control messages
    #         if msg.ep.eptype != 0:
    #             continue

    #         if msg.ep.epdir == 0: # CTRL IN
    #             response = identity.from_request(msg.request)
    #             self.send_usb(USBMessageResponse(ep=self.ep0,request=msg.request,response=response))
    #         else: # CTRL OUT
    #             break

    #     self.disconnect()

    # def run(self):
    #     for c in (3,8):
    #         conf = ConfigurationDescriptor(descriptors=[InterfaceDescriptor(bInterfaceClass=c),EndpointDescriptor()])
    #         identity = DeviceIdentity(conf)
    #         self.start_communication(identity)


if __name__ == "__main__":
    parser = USBScan.create_arg_parser()
    args = parser.parse_args()

    usbscan = USBScan(args)
    usbscan.run()
