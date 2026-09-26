"""Bracketed control: is a host's silence ours, or the network's?

For the whole host list in one window: a stock client to every host, then the
detector once for all of them, then the stock client again. If the stock client
answers on both sides while the detector sees silence, the endpoint is reacting
to the detector's own ClientHello. If it goes quiet too, the path changed between
runs and no verdict can be compared across them.

The detector runs as **one process for all hosts** (it is concurrent inside, and
per-host invocations paid its startup once per row), and the stock-client checks
run in a bounded pool: a 34-host sweep is about a minute rather than eight, with
the bracket still spanning the detector's own window.

Run:  python scripts/quic/bracket.py [host ...]
"""

import asyncio
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated

ROOT = Path(__file__).resolve().parents[2]
EXE = ROOT / "target" / "release-local" / "dpi-detector.exe"
# 8 s, not 4: the probe's own measured window (`QUIC_TIMEOUT` in `config.yml`).
# The endpoint's answer to a *retransmitted* Initial arrives after the first PTO
# (~0.7 s) and sometimes later still, so a 4-second client gives up before it —
# which is how `www.dw.com`, `www.euronews.com` and `www.intel.com` read as
# "no answer" in one pass and `HTTP/3 200`/`403` in the next.
TIMEOUT = 8.0
JOBS = 8


class H3Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.status = None
        self.terminated = None
        self.done = asyncio.Event()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.terminated = (event.error_code, event.reason_phrase)
            self.done.set()
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.status = dict(http_event.headers).get(b":status")
                self.done.set()


async def stock(host, ip):
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
                [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", host.encode()), (b":path", b"/")],
                end_stream=True,
            )
            client.transmit()
            try:
                await asyncio.wait_for(client.done.wait(), timeout=TIMEOUT)
            except asyncio.TimeoutError:
                return "no answer"
            if client.status is not None:
                return f"HTTP/3 {client.status.decode()}"
            code, reason = client.terminated
            if reason and "idle timeout" in reason.lower():
                return "no answer (our idle timeout)"
            return f"closed {code} ({reason})" if reason else f"closed {code}"
    except Exception as error:  # noqa: BLE001
        return f"{type(error).__name__}: {error}"


def detector_rows(hosts):
    """One detector process for the whole list, keyed by the host as asked."""
    args = [str(EXE), "--tests", "2", "--json", "--lang", "en"]
    for host in hosts:
        args += ["-d", host]
    out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=900)
    payload = json.loads(out.stdout[out.stdout.index("{"):])
    rows = {}
    for row in payload["results"]["domain_inspection"]:
        rows[row["domain"]] = (row["resolved"], f"{row['quic']}({row['quic_detail']})")
    return rows


def resolve(host):
    for attempt in range(3):
        try:
            return socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
        except OSError:
            time.sleep(0.5 * (attempt + 1))
    return None


async def pooled(jobs, work, items):
    """Run `work` over `items` with at most `jobs` in flight, keeping the order."""
    gate = asyncio.Semaphore(jobs)

    async def run(item):
        async with gate:
            return await work(item)

    return await asyncio.gather(*(run(item) for item in items))


async def main(hosts):
    addresses = await pooled(JOBS, lambda host: asyncio.to_thread(resolve, host), hosts)
    resolved = {host: ip for host, ip in zip(hosts, addresses) if ip is not None}
    for host, ip in zip(hosts, addresses):
        if ip is None:
            print(f"{host:20} resolve failed (DNS), skipped")
    print(f"stock client, first pass: {len(resolved)} hosts", flush=True)
    before = await pooled(JOBS, lambda host: stock(host, resolved[host]), list(resolved))
    print("detector, one process for the whole list", flush=True)
    mine = await asyncio.to_thread(detector_rows, list(resolved))
    print("stock client, second pass", flush=True)
    after = await pooled(
        JOBS,
        lambda host: stock(host, mine.get(host, (resolved[host], ""))[0] or resolved[host]),
        list(resolved),
    )
    for host, first, second in zip(list(resolved), before, after):
        ip, verdict = mine.get(host, (resolved[host], "no row in --json"))
        print(f"{host:20} stock@{resolved[host]:16} {first:16} | detector@{ip:16} {verdict:34} | stock again {second}")


if __name__ == "__main__":
    # No arguments: the same host list `validate.py` and `crosscheck.py` use,
    # read from the file next to this script (a bare default of one host made a
    # "full sweep" a one-row run).
    hosts = sys.argv[1:]
    if not hosts:
        listing = pathlib.Path(__file__).with_name("hosts.txt")
        hosts = [
            line.strip()
            for line in listing.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    asyncio.run(main(hosts))
