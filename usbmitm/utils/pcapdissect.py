#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
  PcapInjecter
"""

import sys

try:
    import argparse
except:
    print("python-argparse is needed")
    sys.exit(1)

from usbmitm.device.device import USBDevice
from usbmitm.dissect.usbpcap import *
from usbmitm.lib.identity import DeviceIdentity
from usbmitm.dissect.usb import IN, OUT, CTRL
from usbmitm.dissect.usbmitm_proto import *

from scapy.utils import rdpcap
from scapy.config import conf

conf.l2types.register(220, USBPcap)


def parse_args():
    """ Parse command line arguments """
    try:
        import argparse
    except:
        print("python-argparse is needed")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Dissect pcaps")
    parser.add_argument(
        "-p", "--pcap", metavar="PCAP_FILE", required=True, help="Pcap file to load"
    )
    parser.add_argument(
        "-s", "--start", metavar="INTEGER", default=0, type=int, help="Packet to start"
    )
    parser.add_argument(
        "-n",
        "--nb-packets",
        metavar="INTEGER",
        default=0,
        type=int,
        help="Nb packets to inject (0 for all)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    i = 1
    for pkt in rdpcap(args.pcap)[args.start :]:
        print("%u" % i)
        pkt.show()
        i += 1
