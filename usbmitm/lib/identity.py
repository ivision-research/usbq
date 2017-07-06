#!/usr/bin/env python

from collections import defaultdict

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import ManagementNewDevice

class DescriptorList(object):
    def __init__(self,tab):
        self.tab = tab

    def __getitem__(self,i):
        t = filter(self.SELECT,self.tab)
        return t[i]

    def __setitem__(self,i,v):
        t = filter(self.SELECT,self.tab)
        t[i] = v

    def select(self):
        return

class InterfaceList(DescriptorList):
    SELECT=staticmethod(lambda x:type(x) is InterfaceDescriptor)

class EndpointList(DescriptorList):
    SELECT=staticmethod(lambda x:type(x) is EndpointDescriptor)

class StringList(DescriptorList):
    SELECT=staticmethod(lambda x:x)

class DeviceIdentity(object):
    """ Set of usb descriptors that characterize a device """
    DEFAULT_DESCRIPTORS = {
        DEVICE_DESCRIPTOR:[DeviceDescriptor()],
        CONFIGURATION_DESCRIPTOR:[ConfigurationDescriptor(descriptors=[InterfaceDescriptor(),EndpointDescriptor()])],
        STRING_DESCRIPTOR:[StringDescriptor(),StringDescriptor(bString="USBiquitous emulatedd keyboard".encode('utf-16le')),StringDescriptor(bString="USBIQUITOUS".encode('utf-16le'))],
    }
    def __init__(self,descriptors=[],speed=HIGH_SPEED):
        self._load_descriptors(descriptors)
        self.interfaces = InterfaceList(self.configuration.descriptors)
        self.endpoints = EndpointList(self.configuration.descriptors)
        self.strings = StringList(self[STRING_DESCRIPTOR])
        self.speed = speed

    def _load_descriptors(self,descriptors):
        self.descriptors = defaultdict(list)
        if type(descriptors) is list:
            for desc in descriptors:
                self.descriptors[desc.bDescriptorType].append(desc)
        elif type(descriptors) is dict:
            self.descriptors = descriptors
        else:
            self.descriptors[descriptors.bDescriptorType].append(descriptors)

    def __getitem__(self,i):
        if i in self.descriptors:
            return self.descriptors[i]
        else:
            return self.DEFAULT_DESCRIPTORS[i]

    def from_request(self,request):
        """ Return the corresponding Descriptor asked in the request """
        try:
            if request.bDescriptorType == STRING_DESCRIPTOR:
                string_desc = self[STRING_DESCRIPTOR]
                if request.descriptor_index > len(string_desc):
                    res = string_desc[0]
                else:
                    res = string_desc[request.descriptor_index]
            else:
                if request.bDescriptorType == CONFIGURATION_DESCRIPTOR:
                    l = request.wLength
                    res = Descriptor(str(self[request.bDescriptorType][0])[:l])
                else:
                    l = request.wLength
                    res = Descriptor(str(self[request.bDescriptorType][0])[:l])
        except:
            res = None
        return res

    # Device Descriptor access
    def get_device(self):
        return self[DEVICE_DESCRIPTOR][0]
    def set_device(self,desc):
        self.descriptors[DEVICE_DESCRIPTOR] = [desc]
    device = property(get_device,set_device)

    # Configuration descriptor access
    def get_configuration(self):
        return self[CONFIGURATION_DESCRIPTOR][0]
    def set_configuration(self,desc):
        self.descriptors[CONFIGURATION_DESCRIPTOR] = [desc]
    configuration = property(get_configuration,set_configuration)

    # Interface descriptor access
    @property
    def interface(self):
        return self.interfaces

    # Endpoint descriptor access
    @property
    def endpoint(self):
        return self.endpoints

    def set_strings(self,strings):
        for s in strings:
            self.descriptors[3].append(StringDescriptor(bString=s))

    @classmethod
    def from_interface(cls,interface,*args,**kargs):
        """ Create an identity from an interface """
        conf = ConfigurationDescriptor(descriptors=interface.descriptor())
        return cls([conf],*args,**kargs)

    def to_new_identity(self):
        return ManagementNewDevice(speed=self.speed,
                                   device=self.device,
                                   configuration=self.configuration)

if __name__ == "__main__":
    from usbmitm.lib.interface import Interface
    from usbmitm.lib.endpoint import Endpoint
    TestInterface = Interface(descriptors=[Endpoint(1,INT,IN,8,24),Endpoint(1,BULK,OUT,8,24)])
    ident = DeviceIdentity.from_interface(TestInterface)
    ident.configuration.show()
    ident.endpoint[1].bInterval=100
    ident.configuration.show()
