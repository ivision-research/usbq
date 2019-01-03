import pluggy
import attr

__all__ = ['hookimpl', 'USBQPluginDef']

USBQ_EP = 'usbq'

hookspec = pluggy.HookspecMarker('usbq')
hookimpl = pluggy.HookimplMarker('usbq')


@attr.s(frozen=True)
class USBQPluginDef:
    'Define a USBQ plugin.'

    #: Name of the plugin
    name = attr.ib(converter=str)

    #: Description
    desc = attr.ib(converter=str)

    #: Module name
    mod = attr.ib(converter=str)

    #: Class
    clsname = attr.ib(converter=str)

    optional = attr.ib(converter=bool, default=False)


class USBQHookSpec:
    @hookspec
    def usbq_declare_plugins(self):
        '''
        Declare a plugin that can be used for USB packet processing.

        Implementation must return a dict of USBQPluginDef instances.
        '''

    @hookspec(firstresult=True)
    def usbq_wait_for_packet(self):
        '''
        Returns True if data is available from the USB host or device.

        Plugin implementors such as PCAP replay should always
        return True.

        Wait no longer than 1 second before returning.
        '''

    @hookspec(firstresult=True)
    def usbq_host_has_packet(self):
        '''
        Returns True if data is available from the USB host.
        '''

    @hookspec(firstresult=True)
    def usbq_device_has_packet(self):
        '''
        Returns True if data is available from the USB device.
        '''

    @hookspec(firstresult=True)
    def usbq_get_host_packet(self):
        '''
        Get raw data from USB host.
        
        The format of the data is indeterminate as it could be
        sourced from the usbq_core module, pcap file, or some other source.
        Use the decode hook to decode the data prior to usage.

        Implementation must return the packet as bytes.
        '''

    @hookspec(firstresult=True)
    def usbq_get_device_packet(self):
        '''
        Get raw data from USB device.
        
        The format of the data is indeterminate as it could be
        sourced from the usbq_core module, pcap file, or some other source.
        Use the decode hook to decode the data prior to usage.

        Implementation must return the packet as bytes.
        '''

    @hookspec(firstresult=True)
    def usbq_send_device_packet(self, data):
        '''
        Sends raw data to USB device.
        
        The format is not defined and is dependent on the hook implementation.

        :param host: If True then send a packet to the USB Host, otherwise USB Device.
        '''

    @hookspec(firstresult=True)
    def usbq_send_host_packet(self, data):
        '''
        Sends raw data to USB device.
        
        The format is not defined and is dependent on the hook implementation.

        :param host: If True then send a packet to the USB Host, otherwise USB Device.
        '''

    @hookspec(firstresult=True)
    def usbq_host_decode(self, data):
        '''
        Decode a raw USB packet from the host.

        :param data: Raw bytes from USBQ driver.

        Return decoded raw data.
        '''

    @hookspec(firstresult=True)
    def usbq_device_decode(self, data):
        '''
        Decode a raw USB packet from the device.

        :param data: Raw bytes from USBQ driver.

        Return decoded raw data.
        '''

    @hookspec(firstresult=True)
    def usbq_host_encode(self, pkt):
        '''
        Encode a packet to raw data to be sent to the USBQ driver.

        :param pkt: Decoded packet

        Return encoded packet to be sent to the USBQ driver.
        '''

    @hookspec(firstresult=True)
    def usbq_device_encode(self, pkt):
        '''
        Encode a packet to raw data to be sent to the USBQ driver.

        :param pkt: Decoded packet

        Return encoded packet to be sent to the USBQ driver.
        '''

    @hookspec(firstresult=True)
    def usbq_host_mangle(self, pkt):
        '''
        Perform arbitrary mangling of USB host packets.

        :param pkt: Decoded USBQ packet. pkt.content is the USB payload.

        Modify pkt in place. Returned value is ignored.
        '''

    @hookspec(firstresult=True)
    def usbq_device_mangle(self, pkt):
        '''
        Perform arbitrary mangling of USB device packets.

        :param pkt: Decoded USBQ packet. pkt.content is the USB payload.

        Modify pkt in place. Returned value is ignored.
        '''

    @hookspec
    def usbq_log_pkt(self, pkt):
        '''
        Log decoded packet.

        :param pkt: Decoded protocol packet.

        Returned value is ignored.
        '''

