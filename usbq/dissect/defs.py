#
# USB
#

# Endpoint Type
CTRL = 0
ISOC = 1
BULK = 2
INT = 3

# Endpoint Direction
OUT = 0
IN = 1

# SPEED
LOW_SPEED = 1
FULL_SPEED = 2
HIGH_SPEED = 3

# DESCRIPTOR TYPE
DEVICE_DESCRIPTOR = 1
CONFIGURATION_DESCRIPTOR = 2
STRING_DESCRIPTOR = 3
INTERFACE_DESCRIPTOR = 4
ENDPOINT_DESCRIPTOR = 5
BOS_DESCRIPTOR = 0xf
HID_DESCRIPTOR = 0x21
HID_REPORT_DESCRIPTOR = 0x22

# CLASS
HID = 3
MASS_STORAGE = 8

urb_direction = {0: "host-to-device", 1: "device-to-host"}
urb_type = {0: "standard"}
urb_recipient = {0: "device"}
urb_bRequest = {
    1: "GET REPORT",
    6: "GET DESCRIPTOR",
    9: "SET CONFIGURATION",
    0xa: "SET IDLE",
    0xb: "SET INTERFACE",
}
urb_bDescriptorType = {
    DEVICE_DESCRIPTOR: "device",
    CONFIGURATION_DESCRIPTOR: "configuration",
    STRING_DESCRIPTOR: "string",
    INTERFACE_DESCRIPTOR: "interface",
    ENDPOINT_DESCRIPTOR: "endpoint",
    BOS_DESCRIPTOR: "bos",
    HID_DESCRIPTOR: "HID",
    HID_REPORT_DESCRIPTOR: "HID REPORT",
}
urb_language = {0: "no language specified"}

bEndpointDirection = {OUT: "OUT", IN: "IN"}
