import pytest

from scapy.all import raw, rdpcap
from scapy.utils import RawPcapWriter
from usbq.usbpcap import *
from usbq.usbmitm_proto import USBMessageHost


@pytest.fixture
def pcap_writer(tmp_path):
    f = tmp_path / 'test.pcap'
    return RawPcapWriter(f.open('wb'), linktype=220, sync=True)


@pytest.fixture
def pcap_file(pcap_writer):
    binary = b'\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x06\x00\x01\x00\x00@\x00'
    pkt = USBMessageHost(binary)
    msg = pkt.content
    pcap_pkt = USBPcap(usbhost_to_usbpcap(msg))
    pcap_writer.write(raw(pcap_pkt))

    return pcap_writer.filename


def test_read_pcap(pcap_file):
    for packet in rdpcap(pcap_file):
        assert len(packet) > 0
