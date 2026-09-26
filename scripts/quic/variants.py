"""Which property of the hello does an endpoint object to?

The detector's QUIC hello is legal (a strict server accepts it) but unlike a
browser's in ways a browser never is: its transport parameters carry only
`initial_source_connection_id`, so every flow-control limit stays at the RFC's
zero default. This runs a stock client with one such property at a time and
reports what the endpoint does — the experiment that says whether the remaining
`QUIC CLOSED` verdicts are about the hello or about the path.

Run:  python scripts/quic/variants.py www.google.com cloudflare.com
"""

import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

TIMEOUT = 8.0


class H3Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.status = None
        self.terminated = None
        self.handshook = False
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshook = True
        if isinstance(event, ConnectionTerminated):
            self.terminated = (event.error_code, event.reason_phrase)
            self.done.set()
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.status = dict(http_event.headers).get(b":status")
                self.done.set()


async def attempt(host, label, **config):
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
        server_name=host,
        idle_timeout=TIMEOUT,
        **config,
    )
    try:
        async with connect(host, 443, configuration=cfg, create_protocol=H3Probe, wait_connected=False) as client:
            stream_id = client._quic.get_next_available_stream_id()
            client.http.send_headers(
                stream_id,
                [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", host.encode()), (b":path", b"/")],
                end_stream=True,
            )
            client.transmit()
            try:
                await asyncio.wait_for(client.done.wait(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                return f"{label:26} no answer"
            if client.status is not None:
                return f"{label:26} HTTP/3 {client.status.decode()}"
            code, reason = client.terminated
            alert = f" (TLS alert {code - 0x100})" if 0x100 <= code <= 0x1FF else ""
            return f"{label:26} closed {code}{alert} {reason or ''}"
    except Exception as error:  # noqa: BLE001
        return f"{label:26} {type(error).__name__}: {error}"


async def main(hosts):
    for host in hosts:
        print(f"--- {host}")
        print(await attempt(host, "stock"))
        print(await attempt(host, "zeroed flow control", max_data=0, max_stream_data=0))
        print(await attempt(host, "1200-byte datagrams", max_datagram_size=1200))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:] or ["www.google.com"]))
