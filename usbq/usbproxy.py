import attr
import socket
import select
import logging

log = logging.getLogger(__name__)

TIMEOUT = ([], [], [])


@attr.s
class USBProxy:
    'Proxy for a remote USB Host or Device accessible over UDP'

    #: Human-facing device name
    name = attr.ib(converter=str)

    #: Host IP address to connect to or bind to.
    host = attr.ib(converter=str)

    #: Port to connect to or bind to.
    port = attr.ib(converter=int)

    #: Set to True if the proxied USB termination is a USB host. False indicates a USB device.
    device = attr.ib(converter=bool)

    def __attrs_post_init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dst = None

        log.info(
            f'USB proxy setup for {self._devtype} {self.name} ({self.host}:{self.port})'
        )

        if self.device:
            self._setup_device()
        else:
            self._setup_host()

    def _setup_host(self):
        self.dst = (self.host, self.port)

    def _setup_device(self):
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    @property
    def _devtype(self):
        return 'device' if self.device else 'host'

    def data_ready(self, timeout=10, wait_on_error=False):
        '''
        Return True if data is available.

        :param timeout: Timeout, in seconds, to wait for data.
        :param wait_on_error: If select() returns an error then continue to wait for data. Otherwise return False on error.
        '''

        while True:
            log.debug(
                f'Waiting for USB {self._devtype} {self.name} ({self.host}:{self.port})'
            )
            (read, write, error) = select.select([self.sock], [], [self.sock], timeout)
            if error:
                log.error(
                    f'Error waiting for USB {self._devtype} {self.name} ({self.host}:{self.port}): {error}'
                )
                if wait_on_error:
                    continue
                else:
                    return False
            elif read:
                return True
            elif (read, write, error) == TIMEOUT and timeout > 0:
                log.info(
                    f'Timeout waiting for USB {self._devtype} {self.name} ({self.host}:{self.port}): {error}'
                )
                return False

    def read(self):
        'Read a raw USB packet from the remote termination.'

        data, self.dst = self.sock.recvfrom(4096)
        return data

    def write(self, data):
        'Write a raw USB packet to the remote termination.'

        return self.sock.sendto(data, self.dst)
