__all__ = ['USBQException', 'USBQInvocationError', 'USBQDeviceNotConnected']


class USBQException(Exception):
    'Base of all USBQ exceptions'


class USBQInvocationError(USBQException):
    'Error invoking USBQ'


class USBQDeviceNotConnected(USBQException):
    'USBQ device not connected.'
