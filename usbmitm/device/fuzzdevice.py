#!/usr/bin/env python

from threading import Lock
from collections import defaultdict

from usbmitm.dissect.usb import *
from usbmitm.dissect.usbmitm_proto import *
from usbmitm.base import Injecter


class DeviceIdentity(object):
    """ Set of usb descriptors that characterize a device """

    DEFAULT_DESCRIPTORS = {
        1: [DeviceDescriptor()],
        2: [
            ConfigurationDescriptor(
                descriptors=[InterfaceDescriptor(), EndpointDescriptor()]
            )
        ],
        3: [
            StringDescriptor(),
            StringDescriptor(
                bString="USBiquitous emulatedd keyboard".encode('utf-16le')
            ),
            StringDescriptor(bString="USBIQUITOUS".encode('utf-16le')),
        ],
    }

    def __init__(self, descriptors=None):
        self._load_descriptors(descriptors)

    def _load_descriptors(self, descriptors):
        self.descriptors = defaultdict(list)
        if descriptors is not None:
            if type(descriptors) is list:
                for desc in descriptors:
                    self.descriptors[desc.bDescriptorType].append(desc)
            else:
                self.descriptors[descriptors.bDescriptorType].append(descriptors)

    def __getitem__(self, i):
        if i in self.descriptors:
            return self.descriptors[i]
        else:
            return self.DEFAULT_DESCRIPTORS[i]

    def __setitem__(self, i, desc):
        self.descriptors[i] = desc

    def from_request(self, request):
        """ Return the corresponding Descriptor asked in the request """
        if request.bDescriptorType == 3:
            string_desc = self[3]
            if request.descriptor_index > len(string_desc):
                res = string_desc[0]
            else:
                res = string_desc[request.descriptor_index]
        else:
            if request.bDescriptorType == 2:
                l = request.wLength
                res = Descriptor(str(self[request.bDescriptorType][0])[:l])
            else:
                res = self[request.bDescriptorType][0]
        return res


class FuzzDevice(Injecter):
    """ Fuzz a host USB stack """

    fuzzfields = {
        DeviceDescriptor: {"bLength": [0, 255], "bNumConfigurations": [0, 2, 5, 255]},
        ConfigurationDescriptor: {
            "bLength": [0, 255],
            "wTotalLength": [0, 255, 65535],
            "bNumInterfaces": [0, 255],
            "bConfigurationValue": [0, 2, 255],
            "iConfigurationValue": [0, 5, 128, 255],
        },
        InterfaceDescriptor: {
            "bLength": [0, 255],
            "bInterfaceNumber": [0, 255],
            "bAlternateSetting": [0, 254],
            "bNumEndpoint": [0, 5, 255],
            "iInterface": [0, 5, 255],
        },
        EndpointDescriptor: {"bLength": [0, 255]},
        StringDescriptor: {"bLength": [0, 255]},
    }

    def __init__(self, args):
        identity_pkt = ManagementNewDevice(
            speed=3, device=DeviceDescriptor(), configuration=ConfigurationDescriptor()
        )
        super(FuzzDevice, self).__init__(args, identity_pkt)
        self.ep0 = USBEp(epnum=0, eptype=0, epdir=0)
        self.timeout = 15
        self.identity = DeviceIdentity()

    def recv(self):
        if not self.host.wait_for_data(self.timeout):
            return None
        return self.host.read()

    def start_communication(self, fuzzy_descriptor):
        """ Run a fuzz test session """
        self.connect()
        print("Fuzz with %r" % (fuzzy_descriptor,))
        res = False
        last_msg = None
        last_req = False
        while True:
            msg = self.recv()
            if msg is None:
                print("Host Timeout")
                return False
            if last_msg is not None and msg == last_msg:
                print("Same request... aborting")
                res = True
                break
            last_msg = msg
            msg = USBMessageHost(msg)

            # Ignore non USB messages
            if msg.type != 0:
                continue

            msg = msg.content

            # Ignore non control messages
            if msg.ep.eptype != 0:
                continue

            if msg.ep.epdir == 0:  # CTRL IN

                # Do we need to fuzz response ?
                if msg.request.bDescriptorType == fuzzy_descriptor.bDescriptorType:
                    response = fuzzy_descriptor
                    last_req = True
                # Interface and endpoint descriptors are in ConfigurationDescriptor
                elif (
                    msg.request.bDescriptorType == 2
                    and fuzzy_descriptor.bDescriptorType in (4, 5)
                ):
                    response = self.identity.from_request(msg.request)
                    for i in range(len(response.descriptors)):
                        if (
                            response.descriptors[i].bDescriptorType
                            == fuzzy_descriptor.bDescriptorType
                        ):
                            response.descriptors[i] = fuzzy_descriptor
                    last_req = True
                # Not fuzzed descriptor
                else:
                    if last_req:
                        res = True
                        break
                    response = self.identity.from_request(msg.request)
                self.send_usb(
                    USBMessageResponse(
                        ep=self.ep0, request=msg.request, response=response
                    )
                )
            else:  # CTRL OUT
                res = True
                break

        self.disconnect()
        return res

    def run(self):
        for desc, fields in FuzzDevice.fuzzfields.items():
            for field, values in fields.items():
                for value in values:
                    descriptor = desc()
                    setattr(descriptor, field, value)
                    if not self.start_communication(descriptor):
                        print("Host seems to crash with %r" % (descriptor,))
                        return False
        return True


if __name__ == "__main__":
    parser = FuzzDevice.create_arg_parser()
    args = parser.parse_args()

    fuzz = FuzzDevice(args)
    if fuzz.run():
        print("Host still alive")
