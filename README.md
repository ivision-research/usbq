# USBQ

USBQ is a Python-based programming framework for monitoring and modifying USB communications.

This work is MIT licensed.

## Installation

### Userland Installation

`pip install git+https://github.com/rbdixon/usbq.git#egg=usbq`

I'm working on the Pypi package.

### Kernel Module

Right now USBQ requires the kernel module from USBiquitous. I've not modified the module at all and would like to replace this module with mainline kernel capabilities and support for other hardware.

1. Clone [usbq_core](https://github.com/airbus-seclab/usbq_core)
2. Modify `driver.c` line 47 with the IP address of the device that will be executing USBQ.
3. Build the kernel loadable module. The easiest way is to install development tools on your board and then modify the Makefile to be able to find your kernel headers.
4. Install the kernel loadable module.
5. Check your `dmesg` output and see if it is working.

If you have a Beaglebone Black running the `4.4.9-ti-r25` kernel and you want to use a pre-built kernel module configured for IP address `10.0.10.1` you can use the pre-built binary that I've got: [`ubq_core.ko`](https://usbq.org/other/ubq_core.ko). If that pre-built binary breaks you get to keep both pieces.

## Usage

1. Install the loadable kernel module.
2. Plug your MITM board into your host computer.
3. Start USBQ on your MITM host: `usbq mitm`.
4. Plug your USB device into your MITM board.
5. Give it a moment and you should see the USB device pop up on your host computer.
6. Unplug the USB device.
7. Control-C to terminate USBQ.

## Origin

The tool was created for the [edope.bike](https://edope.bike) project and is an extensive rewrite of the userspace component of the [USBiquitous USB Intrusion Toolkit](https://www.sstic.org/media/SSTIC2016/SSTIC-actes/usb_toolkit/SSTIC2016-Article-usb_toolkit-camredon.pdf).
