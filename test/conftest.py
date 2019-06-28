from scapy.config import conf

from usbq.usbpcap import USBPcap

# Configure scapy to parse USB
conf.l2types.register(220, USBPcap)
