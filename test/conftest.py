import pytest

from scapy.config import conf
from usbq.usbpcap import USBPcap

# Configure scapy to parse USB
conf.l2types.register(220, USBPcap)


@pytest.fixture
def proxy_ip():
    return '10.0.10.90'


@pytest.fixture
def proxy_port():
    return 64241


@pytest.fixture
def listen_ip():
    return '10.0.10.1'


@pytest.fixture
def listen_port():
    return 64240
