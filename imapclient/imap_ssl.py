import ssl
import sys
from imaplib import IMAP4_SSL

from .http_proxy_socksocket import HttpProxySockSocket


class SocksIMAP4SSL(IMAP4_SSL):
    def __init__(self,
                 imap_url: str,
                 imap_port: int,
                 proxy_type: int,
                 proxy_host: str,
                 proxy_port: int,
                 proxy_login: str = None,
                 proxy_password: str = None,
                 *args,
                 **kwargs):
        self.proxy_type = proxy_type
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_login = proxy_login
        self.proxy_password = proxy_password
        self.imap_port = imap_port

        IMAP4_SSL.__init__(self, imap_url, imap_port, *args, **kwargs)

    def send(self, data, *args, **kwargs):
        """Send data to remote."""
        sys.audit("imaplib.send", self, data)
        self.sock.sendall(data)

    def open(self, host, port=993, *args, **kwargs):
        self.host = host
        self.port = port

        socket = HttpProxySockSocket()
        socket.set_proxy(
            proxy_type=self.proxy_type,
            addr=self.proxy_host,
            port=self.proxy_port,
            username=self.proxy_login,
            password=self.proxy_password)

        socket.connect((host, port))

        sys.audit("imaplib.open", self, self.host, self.port)
        self.sock = ssl.wrap_socket(socket, self.keyfile, self.certfile)
        self.file = self.sock.makefile('rb')
