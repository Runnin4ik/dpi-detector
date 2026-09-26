"""Cross-check the detector's QUIC column at the address the detector itself used.

Reads the detector's `--json` (`resolved` per domain), then points aioquic at
that same IP - otherwise a "DROP" could just be a different anycast node than
the one Python's getaddrinfo picked, and the comparison would prove nothing.

Run:  python target/quic-crosscheck.py
"""

import asyncio
import json
import socket
import ssl
import subprocess
import sys
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

ROOT = Path(__file__).resolve().parents[2]
EXE = ROOT / "target" / "release-local" / "dpi-detector.exe"
HOSTS = [h.strip() for h in (Path(__file__).resolve().parent / "hosts.txt").read_text().split() if h.strip()]
TIMEOUT = 8.0  # the probe's own window (`QUIC_TIMEOUT`); see bracket.py's note
SEM = asyncio.Semaphore(8)


class H3Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.handshook = False
        self.status = None
        self.terminated = None
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
        async with connect(ip, 443, configuration=cfg, create_protocol=H3Probe, wait_connected=False) as client:
            stream_id = client._quic.get_next_available_stream_id()
            client.http.send_headers(
                stream_id,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", host.encode()),
                    (b":path", b"/"),
                    (b"user-agent", b"quic-crosscheck"),
                ],
                end_stream=True,
            )
            client.transmit()
            try:
                await asyncio.wait_for(client.done.wait(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                if client.status is not None:
                    return f"HTTP/3 {client.status.decode()}"
                return "handshake ok, no response" if client.handshook else "timeout: no reply to our Initial"
            if client.status is not None:
                return f"HTTP/3 {client.status.decode()}"
            code, frame, reason = client.terminated
            if code is None:
                return "closed without a code"
            # aioquic's own idle timeout arrives as INTERNAL_ERROR with this
            # reason: the endpoint never answered, so it is not a close.
            if reason and "idle timeout" in reason.lower():
                return "timeout: no reply to our Initial"
            if 0x100 <= code <= 0x1FF:
                return f"closed {code} = CRYPTO_ERROR, TLS alert {code - 0x100}"
            return f"closed, transport error {code}"
    except ConnectionRefusedError:
        return "refused (ICMP port unreachable)"
    except Exception as error:  # noqa: BLE001
        return f"{type(error).__name__}: {error}"


def alt_svc(host):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: x\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    except Exception as error:  # noqa: BLE001
        return f"- ({type(error).__name__})"
    for line in data.split(b"\r\n"):
        if line.lower().startswith(b"alt-svc:"):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return "absent"


def detector_rows():
    args = [str(EXE), "--tests", "2", "--json", "--lang", "en"]
    for host in HOSTS:
        args += ["-d", host]
    out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=900)
    payload = json.loads(out.stdout[out.stdout.index("{"):])
    rows = {}
    for row in payload["results"]["domain_inspection"]:
        rows[row["domain"]] = row
    return rows


def verdict(mine, theirs):
    if theirs.startswith("HTTP/3"):
        return "NO" if mine != "quic_ok" else "yes"
    if theirs.startswith("timeout"):
        return "yes" if mine == "quic_drop" else "NO"
    if theirs.startswith("refused"):
        return "yes" if mine == "refused" else "NO"
    if theirs.startswith("closed"):
        return "yes" if mine == "quic_closed" else "NO"
    return "?"


async def main():
    rows = await asyncio.to_thread(detector_rows)
    lines = []
    lines.append(f"{'host':23} {'detector':30} {'detector IP':16} {'aioquic at THAT IP':44} agree")
    lines.append("-" * 130)
    agree = 0
    for host in HOSTS:
        row = rows.get(host)
        if row is None:
            lines.append(f"{host:23} {'(no row)':30}")
            continue
        ip = row.get("resolved") or "?"
        detail = row.get("quic_detail") or ""
        mine = row["quic"]
        theirs = await probe(host, ip) if ip != "?" else "no address"
        ok = verdict(mine, theirs)
        agree += ok == "yes"
        tag = mine + (f"({detail})" if detail else "")
        lines.append(f"{host:23} {tag:30} {ip:16} {theirs:44} {ok}")
    lines.append(f"\nсогласие на адресах детектора: {agree}/{len(HOSTS)}")
    text = "\n".join(lines)
    print(text)
    out = ROOT / "target" / "validation" / "crosscheck-latest.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"\n(таблица записана в {out})")


if __name__ == "__main__":
    if not EXE.exists():
        sys.exit(f"no detector at {EXE}")
    asyncio.run(main())
