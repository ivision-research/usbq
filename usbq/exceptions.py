__all__ = ['USBQException', 'USBQDeviceNotConnected']


class USBQException(Exception):
    'Base of all USBQ exceptions'


class USBQDeviceNotConnected(USBQException):
    'USBQ device not connected.'
