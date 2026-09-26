"""Does a real browser complete HTTP/3 with this host?

The column claims to measure *the browser's* QUIC path, so the reference for its
verdicts is a browser, not a minimal Python client: measured, `www.apkmirror.com`
answers a browser-shaped (split, 1740-byte) hello with an Initial carrying no
CRYPTO while a stock client's single-datagram hello gets `HTTP/3 200` - the two
clients are not the same experiment.

This drives a headless Chrome with QUIC forced for one origin, captures the
wire, and reports what the endpoint did with it: a `Handshake` packet and a
`SETTINGS` frame mean the H3 handshake completed, an Initial that opens into
nothing means it did not.

Run:  python scripts/quic/browser_check.py www.apkmirror.com [interface]
"""

import subprocess
import sys
import time
from pathlib import Path

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


def report(path, host):
    out = subprocess.run(
        [TSHARK, "-r", str(path), "-Y", "quic", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "udp.length", "-e", "_ws.col.Info"],
        capture_output=True,
        text=True,
    )
    server_frames = [line for line in out.stdout.splitlines() if line.strip() and not line.split("\t")[1].startswith("192.168.")]
    print(f"{len(server_frames)} server QUIC packets in the capture")
    for line in server_frames[:14]:
        print("   ", line.replace("\t", "  "))
    # A `Handshake` packet, not merely a short-header one: a stateless reset is
    # also a short header and reads as `Protected Payload`, so the weaker test
    # called a reset "completed" (measured on a capture where the endpoint
    # answered a browser with a reset and nothing else).
    completed = any("Handshake" in line for line in server_frames)
    print(f"\n{host}: a real browser {'completed' if completed else 'did NOT complete'} the HTTP/3 handshake")


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
