"""Validate dpi-detector's QUIC column against an independent implementation.

aioquic (a pure-Python RFC 9000/9001/9114 stack) dials the same address the
detector's probe used - the host's A record, not the Alt-Svc authority - and
reports the exact outcome: an HTTP/3 status, the transport error code with the
TLS alert it carries, a timeout, or a refusal.  `wait_connected=False` keeps the
context manager from swallowing a failed handshake as a bare ConnectionError.
The Alt-Svc header, read over TCP, says whether the site advertises h3 at all.

Run:  python target/quic-validate.py
"""

import asyncio
import socket
import ssl

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

HOSTS = [
    ("amnezia.org", "QUIC OK", ""),
    ("aws.amazon.com", "QUIC CLOSED", "296"),
    ("browserleaks.com", "QUIC DROP", ""),
    ("danbooru.donmai.us", "QUIC DROP", ""),
    ("discord.com", "QUIC DROP", ""),
    ("gateway.discord.gg", "QUIC DROP", ""),
    ("holod.media", "QUIC DROP", ""),
    ("hub.docker.com", "QUIC DROP", ""),
    ("media.discordapp.net", "QUIC DROP", ""),
    ("meduza.io", "QUIC DROP", ""),
    ("nnmclub.to", "QUIC DROP", ""),
    ("protonvpn.com", "QUIC DROP", ""),
    ("shikimori.io", "QUIC DROP", ""),
    ("soundcloud.com", "QUIC CLOSED", "296"),
    ("vk.ru", "REFUSED", "icmp"),
    ("www.apkmirror.com", "QUIC CLOSED", "no crypto"),
    ("www.canva.com", "QUIC CLOSED", "no crypto"),
    ("www.cdn77.com", "QUIC CLOSED", "368"),
    ("www.coursera.org", "QUIC CLOSED", "296"),
    ("www.currenttime.tv", "QUIC CLOSED", "336"),
    ("www.dw.com", "QUIC OK", ""),
    ("www.euronews.com", "QUIC OK", ""),
    ("www.facebook.com", "QUIC CLOSED", "reset"),
    ("www.google.com", "QUIC CLOSED", "10"),
    ("www.instagram.com", "QUIC CLOSED", "reset"),
    ("www.intel.com", "QUIC OK", ""),
    ("www.linkedin.com", "QUIC DROP", ""),
    ("www.linuxserver.io", "QUIC DROP", ""),
    ("www.messenger.com", "QUIC CLOSED", "reset"),
    ("www.svoboda.org", "QUIC CLOSED", "336"),
    ("www.themoscowtimes.com", "QUIC DROP", ""),
    ("www.torproject.org", "QUIC DROP", ""),
    ("www.youtube.com", "QUIC CLOSED", "10"),
    ("x.com", "QUIC DROP", ""),
]

TIMEOUT = 8.0  # the probe's own window (`QUIC_TIMEOUT`); see bracket.py's note
SEM = asyncio.Semaphore(8)


class H3Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.handshook = False
        self.status = None
        self.terminated = None
        self.reset = False
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshook = True
        if isinstance(event, ConnectionTerminated):
            self.terminated = (event.error_code, event.frame_type, event.reason_phrase)
            self.done.set()
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.status = dict(http_event.headers).get(b":status")
                self.done.set()


async def probe(host, ip):
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
        server_name=host,
        idle_timeout=TIMEOUT,
    )
    try:
        async with connect(
            ip, 443, configuration=cfg, create_protocol=H3Probe, wait_connected=False
        ) as client:
            stream_id = client._quic.get_next_available_stream_id()
            client.http.send_headers(
                stream_id,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", host.encode()),
                    (b":path", b"/"),
                    (b"user-agent", b"quic-validate"),
                ],
                end_stream=True,
            )
            client.transmit()
            try:
                await asyncio.wait_for(client.done.wait(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                if client.status is not None:
                    return f"HTTP/3 {client.status.decode()}"
                if client.handshook:
                    return "handshake ok, then no response in the window"
                return "timeout: no reply to our Initial"
            if client.status is not None:
                return f"HTTP/3 {client.status.decode()} (handshake completed)"
            code, frame, reason = client.terminated
            if reason and "idle timeout" in reason.lower():
                return "timeout: no reply to our Initial"
            if code is None:
                return "closed without a code"
            if 0x100 <= code <= 0x1FF:
                return f"closed {code} = CRYPTO_ERROR, TLS alert {code - 0x100}"
            return f"closed, transport error {code}"
    except ConnectionRefusedError:
        return "refused (ICMP port unreachable)"
    except Exception as error:  # noqa: BLE001 - aioquic raises its own types
        return f"{type(error).__name__}: {error}"


def alt_svc(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: quic-validate\r\nConnection: close\r\n\r\n"
                tls.sendall(request.encode())
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except Exception as error:  # noqa: BLE001 - the point is to report anything
        return f"- ({type(error).__name__})"
    for line in data.split(b"\r\n"):
        if line.lower().startswith(b"alt-svc:"):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return "absent"


def resolve(host):
    try:
        return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except OSError as error:
        return f"!{error}"


async def one(host, mine, detail, results):
    async with SEM:
        ip = resolve(host)
        if ip.startswith("!"):
            results[host] = (mine, detail, ip, ip, "-")
            return
        theirs = await probe(host, ip)
        svc = await asyncio.to_thread(alt_svc, host)
        results[host] = (mine, detail, ip, theirs, svc)


def verdict(mine, theirs, svc):
    """Does the independent client confirm the detector's row?"""
    if theirs.startswith("HTTP/3"):
        return "NO" if mine != "QUIC OK" else "yes"
    if theirs.startswith("timeout"):
        return "yes" if mine in ("QUIC DROP", "REFUSED") else "NO"
    if theirs.startswith("refused"):
        return "yes" if mine == "REFUSED" else "NO"
    if theirs.startswith("closed"):
        return "yes" if mine == "QUIC CLOSED" else "NO"
    return "?"


async def main():
    results = {}
    await asyncio.gather(*(one(h, m, d, results) for h, m, d in HOSTS))
    rows = [(h, *results[h]) for h, _, _ in HOSTS]
    print(f"{'host':23} {'detector':14} {'aioquic (independent)':44} {'alt-svc':14} agree")
    print("-" * 120)
    for host, mine, detail, ip, theirs, svc in sorted(rows, key=lambda r: (r[1], r[0])):
        tag = f"{mine}" + (f"({detail})" if detail else "")
        ok = verdict(mine, theirs, svc)
        print(f"{host:23} {tag:14} {theirs:44} {svc.split(';')[0][:14]:14} {ok}")
    agree = sum(1 for r in rows if verdict(r[1], r[4], r[5]) == "yes")
    print(f"\nсогласие: {agree}/{len(rows)}; расхождений: {sum(1 for r in rows if verdict(r[1], r[4], r[5]) == 'NO')}")
    print("\nA-записи (по ним шли обе стороны):")
    for host, _, _, ip, _, _ in sorted(rows):
        print(f"  {host:23} {ip}")


if __name__ == "__main__":
    asyncio.run(main())
