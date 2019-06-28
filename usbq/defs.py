from frozendict import frozendict

__all__ = ['USBDefs', 'URBDefs']


class AutoDescEnum:
    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)

        # Build a dict with descriptions for each field value.
        # This is used for scapy packet display.
        cls.desc = frozendict(
            {
                getattr(cls, key): f'{key} (0x{getattr(cls, key):02x})'
                for key in dir(cls)
                if not key.startswith('_')
            }
        )

        assert cls.__doc__ is not None, 'Add documentation to enumeration'

        # Update documentation with values
        cls.__doc__ += '\n\n'
        for key, value in sorted(cls.desc.items(), key=lambda kv: kv[0]):
            cls.__doc__ += f'{key}: {value}\n'

    def __class_getitem__(cls, key):
        return cls.desc.get(key, f'[UNKNOWN] (0x{key:02x})')


class USBDefs:
    'USB field values'

    class EP:
        'Endpoint field values'

        class TransferType(AutoDescEnum):
            'USB endpoint transfer types'
            CTRL = 0
            ISOC = 1
            BULK = 2
            INT = 3

        class Direction(AutoDescEnum):
            'Endpoint Direction'
            OUT = 0
            IN = 1

    class Speed(AutoDescEnum):
        'USB Speed'
        LOW_SPEED = 1
        FULL_SPEED = 2
        HIGH_SPEED = 3

    class DescriptorType(AutoDescEnum):
        'Descriptor Type'
        DEVICE_DESCRIPTOR = 1
        CONFIGURATION_DESCRIPTOR = 2
        STRING_DESCRIPTOR = 3
        INTERFACE_DESCRIPTOR = 4
        ENDPOINT_DESCRIPTOR = 5
        BOS_DESCRIPTOR = 0xF
        HID_DESCRIPTOR = 0x21
        HID_REPORT_DESCRIPTOR = 0x22

    class DeviceClass(AutoDescEnum):
        'Device class'
        HID = 3
        MASS_STORAGE = 8


class URBDefs:
    '''
    USB Request Block field values

    See https://www.kernel.org/doc/html/v4.15/driver-api/usb/URB.html
    '''

    class Direction(AutoDescEnum):
        'Direction of request'
        HOST_TO_DEVICE = 0
        DEVICE_TO_HOST = 1

    class Type(AutoDescEnum):
        'Type of request'
        STANDARD = 0

    class Recipient(AutoDescEnum):
        'Recipient of request'
        DEVICE = 0

    class Request(AutoDescEnum):
        'Request type'
        GET_REPORT = 1
        GET_DESCRIPTOR = 6
        SET_CONFIGURATION = 9
        SET_IDLE = 0xA
        SET_INTERFACE = 0xB

    class Language(AutoDescEnum):
        'Language of string descriptor request'
        NONE_SPECIFIED = 0

    DescriptorType = USBDefs.DescriptorType
