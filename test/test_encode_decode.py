import pytest

from scapy.all import raw
from usbq.plugins.encode import USBEncode
from usbq.plugins.decode import USBDecode


def test_decode_encode():
    data = b'\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x06\x00\x01\x00\x00@\x00'
    decoder = USBDecode()
    encoder = USBEncode()
    pkt = decoder.usbq_host_decode(data=data)
    assert data == encoder.usbq_host_encode(pkt=pkt)
