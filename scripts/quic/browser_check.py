"""Does a real browser complete HTTP/3 with this host?

The column claims to measure *the browser's* QUIC path, so the reference for its
verdicts is a browser, not a minimal Python client: measured, `www.apkmirror.com`
answers a browser-shaped (split, 1740-byte) hello with an Initial carrying no
CRYPTO while a stock client's single-datagram hello gets `HTTP/3 200` - the two
clients are not the same experiment.

This drives a headless Chrome with QUIC forced for one origin, captures the
wire, and reports what the endpoint did with it: a `Handshake` packet and a
`SETTINGS` frame mean the H3 handshake completed, an Initial that opens into
nothing means it did not. Only the connection whose ClientHello carried the
host's SNI is read (`tp_dump.py`'s reassembly, imported): Chrome's own
background QUIC and the host's NATed outbound packets are not this host's
answer, and the address the browser used is printed because an endpoint's
verdict belongs to one address, not to a name.

Run:  python scripts/quic/browser_check.py www.apkmirror.com [interface]
"""

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decrypt import parse_long_header  # noqa: E402
from tp_dump import assemble, crypto_of, extensions, open_client  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
DUMPCAP = r"C:\Program Files\Wireshark\dumpcap.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
DEFAULT_INTERFACE = r"\Device\NPF_{2D03CDCB-E549-4703-89C3-A8BFD9BC8A5F}"


def capture(host, interface, seconds, out):
    cap = subprocess.Popen(
        [DUMPCAP, "-i", interface, "-f", "udp port 443", "-w", str(out), "-a", f"duration:{seconds}"],
        # Not PIPE: nobody reads it, the buffer fills, and dumpcap blocks before
        # its own duration expires (measured - the first version hung here).
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2.5)
    profile = ROOT / "target" / f"chrome-{host.replace('.', '-')}"
    subprocess.run(
        [
            CHROME,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            f"--user-data-dir={profile}",
            f"--origin-to-force-quic-on={host}:443",
            "--dump-dom",
            f"https://{host}/",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    cap.wait(timeout=seconds + 30)


def frames(path):
    """Every QUIC frame of the capture: its raw line, the addresses, the payload.

    The read `tp_dump.py` makes (`udp.payload`), plus the two addresses the
    verdict needs: which connection a packet belongs to is a question about who
    sent it to whom.
    """
    out = subprocess.run(
        [TSHARK, "-r", str(path), "-Y", "quic", "-T", "fields", "-e", "frame.number", "-e", "ip.src",
         "-e", "ip.dst", "-e", "udp.length", "-e", "udp.payload", "-e", "_ws.col.Info"],
        capture_output=True,
        text=True,
    )
    seen = []
    for line in out.stdout.splitlines():
        _, src, dst, _length, payload, info = (line.split("\t") + [""] * 6)[:6]
        if not src or not dst or not payload:
            continue
        try:
            packet = bytes.fromhex(payload)
        except ValueError:
            continue
        # 21 bytes is the floor for a stateless reset (RFC 9000 10.3), the
        # smallest packet this script has anything to say about; a frame with no
        # IPv4 address (IPv6 traffic, malformed) is skipped above.
        if len(packet) < 21:
            continue
        seen.append({"line": line.replace("\t", "  "), "src": src, "dst": dst, "packet": packet, "info": info})
    return seen


def connections(seen):
    """Every client connection in the capture, keyed by its ClientHello's SNI.

    `tp_dump.py`'s reassembly, imported rather than written a second time:
    Chrome splits its ClientHello over two Initials, so the CRYPTO chunks of
    every packet carrying one DCID have to be joined before the SNI is there to
    read. Without the SNI, the endpoint's own packets cannot be told from
    Chrome's background QUIC to another host.
    """
    streams = {}
    meta = {}
    for frame in seen:
        packet = frame["packet"]
        if packet[0] & 0x80 == 0:
            continue
        try:
            _, dcid, scid, _, _, _ = parse_long_header(packet)
            plain = open_client(packet, dcid)
        except Exception:  # noqa: BLE001 - a server packet, or a connection we cannot open
            continue
        streams.setdefault(dcid, []).extend(crypto_of(plain))
        meta.setdefault(dcid, (frame["src"], frame["dst"], scid))
    out = {}
    for dcid, chunks in streams.items():
        hello = assemble(chunks)
        if len(hello) < 8 or hello[0] != 0x01:
            continue
        sni = next(
            (body[5:].decode("latin-1", "replace") for kind, body in extensions(hello) if kind == 0x00),
            None,
        )
        if not sni:
            continue
        client_ip, server_ip, client_cid = meta[dcid]
        out[dcid] = {"sni": sni, "client_ip": client_ip, "server_ip": server_ip, "client_cid": client_cid}
    return out


def dcid_of(packet):
    """The DCID of a long header, or None when the packet is too short to carry one."""
    try:
        return parse_long_header(packet)[1]
    except (IndexError, ValueError):
        return None


def report(path, host):
    seen = frames(path)
    found = connections(seen)
    match = next(((dcid, one) for dcid, one in found.items() if one["sni"] == host), None)
    if match is None:
        print("connections seen: " + (", ".join(sorted(one["sni"] for one in found.values())) or "none"))
        print(f"\n{host}: no ClientHello with this SNI in the capture, so the verdict cannot be "
              f"scoped to a connection and none is printed")
        return
    dcid, one = match
    server_ip, client_ip = one["server_ip"], one["client_ip"]
    print(f"the browser used {server_ip}:443 for {host} (connection DCID={dcid.hex()} from {client_ip})")
    # Every QUIC packet not from `192.168.*` includes Chrome's own background
    # QUIC to Google and the host's NATed outbound traffic, so a `Handshake`
    # anywhere in the capture is not this host's answer. A long header carries
    # the CID, so it counts only when addressed to the identifier this
    # connection's client chose; a short header carries none and the 5-tuple is
    # all there is - the reset this script has to read is one of those.
    server_frames = [
        frame
        for frame in seen
        if frame["src"] == server_ip
        and frame["dst"] == client_ip
        and (frame["packet"][0] & 0x80 == 0 or dcid_of(frame["packet"]) == one["client_cid"])
    ]
    print(f"{len(server_frames)} QUIC packets from {server_ip} on this connection")
    for frame in server_frames[:14]:
        print("   ", frame["line"])
    # A `Handshake` packet, not merely a short-header one: a stateless reset is
    # also a short header and reads as `Protected Payload`, so the weaker test
    # called a reset "completed" (measured on a capture where the endpoint
    # answered a browser with a reset and nothing else).
    completed = any("Handshake" in frame["info"] for frame in server_frames)
    print(f"\n{host}: a real browser {'completed' if completed else 'did NOT complete'} "
          f"the HTTP/3 handshake with {server_ip}")


def main(host, interface):
    out = ROOT / "target" / "validation" / f"browser-{host.replace('.', '-')}.pcapng"
    out.parent.mkdir(parents=True, exist_ok=True)
    capture(host, interface, 35, out)
    report(out, host)


if __name__ == "__main__":
    main(
        sys.argv[1] if len(sys.argv) > 1 else "www.apkmirror.com",
        sys.argv[2] if len(sys.argv) > 2 else DEFAULT_INTERFACE,
    )
