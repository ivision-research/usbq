#!/usr/bin/env python

import time

from .hid import HIDDevice
from usbmitm.dissect.hid import *
from usbmitm.utils.speed import ls2hs_interval
from usbmitm.dissect.usbmitm_proto import USBEp, USBMessageResponse
from usbmitm.lib.interface import Interface
from usbmitm.lib.endpoint import Endpoint
from usbmitm.lib.identity import DeviceIdentity

from usbmitm.dissect.usb import *
from usbmitm.dissect.hid import *
from usbmitm.dissect.usbpcap import *

report_descriptor = "05010902a1010901a100050919012903150025019503750181029505810305010930093109381581257f750895038106c0c0".decode(
    "hex"
)
hid_descriptor = HIDDescriptor(
    descriptors=[HIDReportDescriptor(wDescriptorLength=len(report_descriptor))]
)
MouseInterface = Interface(
    descriptors=[Endpoint(1, INT, IN, 4, ls2hs_interval(10)), hid_descriptor],
    cls=HID,
    subcls=1,
    proto=HID_PROTOCOL_MOUSE,
)


class Mouse(HIDDevice):
    def __init__(self, args):
        ident = DeviceIdentity.from_interface(MouseInterface, speed=LOW_SPEED)
        ident.set_strings(
            [
                "\x09\x04",
                "USBiquitous emulated mouse".encode('utf-16le'),
                "USBIQUITOUS".encode('utf-16le'),
            ]
        )
        super(Mouse, self).__init__(args, ident, report_descriptor)
        self.ep1 = USBEp(epnum=1, eptype=INT, epdir=0)

    def send_event(self, event):
        self.send_in_data(USBMessageResponse(ep=self.ep1, data=event))
        time.sleep(0.01)


conf.l2types.register(220, USBPcap)


class MousePCAP(Mouse):
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--pcap", "-p", metavar="FILE", help="File to run")
        parser.add_argument(
            "-s",
            "--start",
            metavar="INTEGER",
            default=0,
            type=int,
            help="Packet to start",
        )
        parser.add_argument(
            "-n",
            "--nb-packets",
            metavar="INTEGER",
            default=0,
            type=int,
            help="Nb packets to inject (0 for all)",
        )

    def __init__(self, args):
        super(MousePCAP, self).__init__(args)
        self.pcap = args.pcap
        self.start = args.start
        self.nb = args.nb_packets

    def match(self, pkt):
        """ Return True if pkt match a data mouse pkt """
        return (
            pkt.urb_type == COMPLETE
            and pkt.urb_transfert == PCAP_INT
            and pkt.endpoint_direction == IN
        )

    def run(self):
        self.init()
        time.sleep(1)
        i = 0
        nb = 0
        for pkt in PcapReader(self.pcap):
            i += 1
            if i <= self.start:
                continue
            pkt = pkt[0]
            if self.match(pkt):
                self.send_event(pkt.data)
                nb += 1
                print(nb)
                if nb == self.nb:
                    break
        self.disconnect()


if __name__ == "__main__":
    parser = MousePCAP.create_arg_parser()
    args = parser.parse_args()

    mouse = MousePCAP(args)
    mouse.run()
