import attr
import logging

from scapy.all import raw
from collections import defaultdict

from ..dissect.defs import *
from ..dissect.usb import *
from ..usbmitm_proto import ManagementNewDevice

__all__ = ['DeviceIdentity']

log = logging.getLogger(__name__)


@attr.s
class DescriptorList:
    tab = attr.ib(converter=lambda v: v or [], default=[])

    def __getitem__(self, i):
        t = list(filter(self.SELECT, self.tab))
        return t[i]

    def __setitem__(self, i, v):
        t = list(filter(self.SELECT, self.tab))
        t[i] = v

    def __len__(self):
        return len(list(filter(self.SELECT, self.tab)))

    def select(self):
        return


class InterfaceList(DescriptorList):
    SELECT = staticmethod(lambda x: type(x) is InterfaceDescriptor)


class EndpointList(DescriptorList):
    SELECT = staticmethod(lambda x: type(x) is EndpointDescriptor)


class StringList(DescriptorList):
    SELECT = staticmethod(lambda x: x)


DEFAULT_DESCRIPTORS = {
    DEVICE_DESCRIPTOR: DeviceDescriptor(),
    CONFIGURATION_DESCRIPTOR: [
        ConfigurationDescriptor(
            descriptors=[InterfaceDescriptor(), EndpointDescriptor()]
        )
    ],
    STRING_DESCRIPTOR: [
        # Supported languages
        StringDescriptor(),
        StringDescriptor(bString='USBIQUITOUS'.encode('utf-16le')),
        StringDescriptor(
            bString='USBiquitous emulated generic device'.encode('utf-16le')
        ),
        StringDescriptor(bString='0xDEADBEEF'.encode('utf-16le')),
    ],
}


def to_descriptor_dict(v):
    res = defaultdict(list)
    if type(v) is list:
        for desc in v:
            res[desc.bDescriptorType].append(desc)
    elif type(v) is dict:
        res = v
    else:
        res[v.bDescriptorType].append(v)
    return res


@attr.s
class DeviceIdentity:
    ''' Set of usb descriptors that characterize a device '''

    descriptors = attr.ib(converter=to_descriptor_dict, default=DEFAULT_DESCRIPTORS)
    speed = attr.ib(default=HIGH_SPEED)

    @classmethod
    def from_interface(cls, interface, *args, **kargs):
        ''' Create an identity from an interface '''
        conf = ConfigurationDescriptor(descriptors=interface.descriptors)
        return cls([conf], *args, **kargs)

    def __getitem__(self, i):
        if i in self.descriptors:
            return self.descriptors[i]

    def from_request(self, request):
        ''' Return the corresponding Descriptor asked in the request '''
        try:
            if request.bDescriptorType == STRING_DESCRIPTOR:
                string_desc = self[STRING_DESCRIPTOR]
                if request.descriptor_index > len(string_desc):
                    res = string_desc[0]
                else:
                    res = string_desc[request.descriptor_index]
            else:
                # Conversion to raw is used to trim descriptor if required by host
                if request.bDescriptorType == CONFIGURATION_DESCRIPTOR:
                    l = request.wLength
                    res = Descriptor(raw(self[request.bDescriptorType][0])[:l])
                else:
                    l = request.wLength
                    res = Descriptor(raw(self[request.bDescriptorType])[:l])
        except Exception as e:
            log.error(f'Could not lookup descriptor from request: {repr(request)}')
            res = None
        return res

    # Device Descriptor access
    @property
    def device(self):
        return self[DEVICE_DESCRIPTOR][0]

    @device.setter
    def device(self, desc):
        self.descriptors[DEVICE_DESCRIPTOR] = [desc]

    # Configuration descriptor access
    @property
    def configuration(self):
        return self[CONFIGURATION_DESCRIPTOR][0]

    @configuration.setter
    def configuration(self, desc):
        self.descriptors[CONFIGURATION_DESCRIPTOR] = [desc]

    @property
    def interfaces(self):
        return InterfaceList(self.configuration.descriptors)

    @property
    def endpoints(self):
        return EndpointList(self.configuration.descriptors)

    @property
    def strings(self):
        return StringList(self[STRING_DESCRIPTOR])

    def set_strings(self, strings):
        for s in strings:
            self.descriptors[STRING_DESCRIPTOR].append(StringDescriptor(bString=s))

    def to_new_identity(self):
        return ManagementNewDevice(
            speed=self.speed, device=self.device, configuration=self.configuration
        )