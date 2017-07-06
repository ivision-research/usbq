#!/usr/bin/env python

import time

from usbmitm.dissect.usbmitm_proto import USBEp,USBMessageResponse
from usbmitm.lib.interface import Interface
from usbmitm.lib.endpoint import Endpoint
from usbmitm.lib.identity import DeviceIdentity

from usbmitm.dissect.usb import *
from usbmitm.dissect.hid import ReportDescriptor
from usbmitm.device.keyboard import Keyboard

from azerty import *

# Taken from scapy : scapy/utils.py
def corrupt_bytes(s, p=0.01, n=None):
    """Corrupt a given percentage or number of bytes from a string"""
    s = array.array("B",str(s))
    l = len(s)
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i] = (s[i]+random.randint(1,255))%256
    return s.tostring()

# Taken from scapy : scapy/utils.py
def corrupt_bits(s, p=0.01, n=None):
    """Flip a given percentage or number of bits from a string"""
    s = array.array("B",str(s))
    l = len(s)*8
    if n is None:
        n = max(1,int(l*p))
    for i in random.sample(xrange(l), n):
        s[i/8] ^= 1 << (i%8)
    return s.tostring()

class ReportFuzzer(Keyboard):
    RELEASE = "\x00\x00\x00\x00\x00\x00\x00\x00"

    @classmethod
    def create_arg_subparser(cls,parser):
        parser.add_argument("--input","-i",metavar="FILE",help="File to run")
        parser.add_argument("--seed",metavar="SEED",type=int,help="Set seed for random values to be reproductible")
        parser.add_argument("--bytes","-B",action="store_true",help="If set then corrupt byte will be set instead of corrupt bits")
        parser.add_argument("--percentage-pkt",metavar="PERCENTAGE",default=0.01,type=float,help="Percentage of packet modified")
        parser.add_argument("--number","-n",metavar="NUMBER",default=None,type=int,help="Number of bits/bytes fuzzed inside a packet")
        parser.add_argument("--percentage","-c",metavar="PERCENTAGE",default=0.01,type=float,help="Percentage of bits/bytes fuzzed inside a packet (will be override by number if set)")
        parser.add_argument("--random-vid",action="store_true",help="Randomize vendor ID")
        parser.add_argument("--random-pid",action="store_true",help="Randomize product ID")
        parser.add_argument("--fuzz-payload",action="store_true",help="Fuzz payload")
        parser.add_argument("endpoints",metavar="ENDPOINTS",nargs="*",help="Endpoints to fuzz: ctr1in,bul0out,int1out... (empty for all) ")


    def __init__(self,args):
        super(ReportFuzzer,self).__init__(args)
        if args.random_vid:
            self.identity[DEVICE_DESCRIPTOR][0].idVendor = random.randint(0,65535)
        if args.random_pid:
            self.identity[DEVICE_DESCRIPTOR][0].idProduct = random.randint(0,65535)
        self.input = args.input
        if args.bytes:
            self.corrupt = corrupt_bytes
        else:
            self.corrupt = corrupt_bits

        self.number = args.number
        self.percentage = args.percentage
        self.percentage_pkt = args.percentage_pkt

        # To be reproductible
        if not args.seed is None:
            random.seed(args.seed)

    def wait_for_hid_report(self):
        pass

    def hid_request_received(self):
        pass

    def need_hid_report(self):
        pass

    def load(self,delta=0.2):
        r = []
        with open(self.input,"r") as f:
            data = f.read()
        for c in data:
            scan = get_scan_code(c)
            if scan is not None:
                r.append((scan,delta))
                r.append((Keyboard.RELEASE,delta))
            else:
                print "WRN: Unable to interpret %c (0x%02x)" % (c,ord(c))
        return r

    def run(self):
        i = 0
        while True:
            report = "05010902a10185020901a1000509190129101500250195107501810205011601f826ff07750c95020930093181061581257f7508950109388106050c0a380295018106c0c0050c0901a1018503751095021501268c0219012a8c028100c005010980a10185047502950115012503098209810983816075068103c006bcff0988a1018508190129ff150126ff00750895018100c0".decode("hex")
            report = self.corrupt(report,self.percentage,self.number)
            print "%u) Report SENT: %r" % (i,report,)
            self.report_descriptor = {0:report}
            self.init()
            time.sleep(2)
            for scan,pause in self.load():
                if self.args.fuzz_payload:
                    scan = corrupt_bytes(scan,1)
                self.send_event(scan)
                time.sleep(pause)
            self.disconnect()
            i += 1


if __name__ == "__main__":
    parser = ReportFuzzer.create_arg_parser()
    args = parser.parse_args()

    ducky = ReportFuzzer(args)
    ducky.run()
