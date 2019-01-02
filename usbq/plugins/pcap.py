import attr
import logging

from scapy.utils import RawPcapWriter
from scapy.all import raw

from ..pm import pm
from ..hookspec import hookimpl
from ..usbpcap import *
from ..usbmitm_proto import USBMessageHost, USBMessageDevice, PROTO_OUT
from ..dissect.defs import CTRL

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class PcapFileWriter:
    'Write a PCAP file containing all proxied USB traffic.'

    #: Filename for the PCAP file.
    pcap = attr.ib(converter=str)

    def __attrs_post_init__(self):
        self._pcap = RawPcapWriter(self.pcap, linktype=220, sync=True)

    def _do_host(self, msg):
        # Convert and write
        pcap_pkt = usbhost_to_usbpcap(msg)
        log.debug(pcap_pkt)
        self._pcap.write(raw(pcap_pkt))

        # We do not receive ACK from device for OUT data
        if msg.ep.epdir == PROTO_OUT:
            ack = ack_from_msg(msg)
            self._pcap.write(raw(ack))

    def _do_device(self, msg):
        # We do not receive REQUEST from host if type is not CTRL
        if msg.ep.eptype != CTRL:
            req = req_from_msg(msg)
            self._pcap.write(raw(req))

        # Convert and write
        pcap_pkt = usbdev_to_usbpcap(msg)
        self._pcap.write(raw(pcap_pkt))

    @hookimpl
    def usbq_log_pkt(self, pkt):
        # Only log USB type packets to the pcap file
        if pkt.type != 0:
            return

        msg = pkt.content
        if type(pkt) == USBMessageDevice:
            self._do_device(msg)
        else:
            self._do_host(msg)

