import pytest

from usbq.plugins.proxy import ProxyPlugin

DATA = b'1234'


@pytest.fixture()
def proxy():
    'Setup proxy in a loopback configuration.'

    proxy = ProxyPlugin(
        device_addr='127.0.0.1',
        device_port=55555,
        host_addr='127.0.0.1',
        host_port=55555,
    )
    assert not proxy.usbq_device_has_packet()
    assert not proxy.usbq_host_has_packet()
    return proxy


@pytest.mark.timeout(1)
def test_send_recv(proxy):
    # Host send
    proxy.usbq_send_host_packet(DATA)

    while not proxy.usbq_device_has_packet():
        pass

    assert proxy.usbq_get_device_packet() == DATA
    assert not proxy.usbq_device_has_packet()

    # Host recv
    proxy.usbq_send_device_packet(DATA)

    while not proxy.usbq_host_has_packet():
        pass

    assert proxy.usbq_get_host_packet() == DATA
    assert not proxy.usbq_host_has_packet()


@pytest.mark.timeout(1)
def test_no_wait(proxy):
    assert not proxy.usbq_device_has_packet()
    assert not proxy.usbq_host_has_packet()
