import logging

import attr
from scapy.all import hexdump

from ..hookspec import hookimpl

log = logging.getLogger(__name__)


@attr.s(cmp=False)
class Hexdump:
    'Print packets as a hexdump to the console.'

    @hookimpl
    def usbq_log_pkt(self, pkt):
        # Dump to console
        log.info(repr(pkt))

        if hasattr(pkt, 'content'):
            hexdump(pkt.content)
            print()
