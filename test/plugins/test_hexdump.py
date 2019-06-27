import pytest

from usbq.plugins.hexdump import Hexdump
from usbq.usbmitm_proto import USBMessageDevice, USBMessageHost


@pytest.mark.parametrize('cls', [USBMessageDevice, USBMessageHost])
def test_hexdump(capsys, cls):
    pkt = cls()
    assert hasattr(pkt, 'content')
    Hexdump().usbq_log_pkt(pkt)
    captured = capsys.readouterr()
    assert len(captured.out) > 0
