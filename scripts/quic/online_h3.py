"""What does a site support, independent of our own network?

The column measures the *path from here*; this asks the other question — does the
host serve HTTP/3 at all — from two third-party testers on networks that are not
ours, so a disagreement separates "the site has no HTTP/3" from "our path to it
does not work". Measured: `gateway.discord.gg` and `hub.docker.com` answer a
handshake from the testers' networks and close ours with a TLS `handshake_failure`
(296), which is exactly the difference a censored user needs to see.

Two testers, because one is one implementation:
  * `intodns.ai/api/web/http3` — JSON: Alt-Svc, the RFC 9460 HTTPS record, and a
    QUIC probe from their host.
  * `http3check.net` — LiteSpeed's, which runs the handshake itself and reports
    whether QUIC and HTTP/3 are supported.

Writes `target/validation/online-h3.txt` and prints the same table.

Run:  python scripts/quic/online_h3.py [host ...]
"""

import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "target" / "validation" / "online-h3.txt"
INTODNS = "https://intodns.ai/api/web/http3?domain={}"
HTTP3CHECK = "https://http3check.net/?host={}"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) dpi-detector-quic-stand"


def fetch(url, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def retrying(url, attempts=4, pause=8.0):
    """Third-party APIs rate-limit: back off on 429 rather than reporting a gap."""
    for attempt in range(attempts):
        try:
            return fetch(url)
        except urllib.error.HTTPError as error:
            if error.code == 429 and attempt + 1 < attempts:
                time.sleep(pause * (attempt + 1))
                continue
            return f"ERROR {error.code}"
        except Exception as error:  # noqa: BLE001
            return f"ERROR {type(error).__name__}"
    return "ERROR retries exhausted"


def intodns(host):
    body = retrying(INTODNS.format(host))
    if body.startswith("ERROR"):
        return body, "-", "-", "-"
    try:
        payload = json.loads(body)
    except ValueError:
        return "ERROR parse", "-", "-", "-"
    record = payload.get("httpsRecord") or {}
    probe = payload.get("quicProbe") or {}
    methods = payload.get("detectionMethods") or {}
    probe_state = "ok" if probe.get("success") else ("inconclusive" if probe.get("inconclusive") else "fail")
    alpn = ",".join(record.get("alpn") or []) or "-"
    return (
        "yes" if payload.get("http3Supported") else "no",
        f"alt-svc={methods.get('altSvc')}",
        f"alpn={alpn}",
        f"quic={probe_state}",
    )


def http3check(host):
    body = retrying(HTTP3CHECK.format(host))
    if body.startswith("ERROR"):
        return body, "-"
    if "HTTP/3 is supported" in body and "HTTP/3 is not supported" not in body:
        supported = "yes"
    elif "HTTP/3 is not supported" in body or "does not advertise any alternative services" in body:
        # The wording a host without HTTP/3 gets: "HTTP/3 Check could not get the
        # server's advertised QUIC versions ... Server does not advertise any
        # alternative services."
        supported = "no"
    else:
        supported = "unknown"
    quic = "yes" if re.search(r"QUIC is supported", body) else ("no" if "QUIC is not supported" in body else "-")
    versions = "-"
    match = re.search(r"QUIC Versions.{0,4000}?h3[-0-9, ]*", body, re.S)
    if match:
        versions = " ".join(sorted(set(re.findall(r"\bh3(?:-\d+)?\b", match.group(0))))) or "-"
    return supported, f"quic={quic} versions={versions}"


def main(hosts):
    rows = [f"{'host':24} {'intodns':8} {'http3check':10} detail"]
    for host in hosts:
        first, alt_svc, alpn, probe = intodns(host)
        time.sleep(1.0)
        second, versions = http3check(host)
        rows.append(f"{host:24} {first:8} {second:10} {alt_svc} {alpn} {probe} | {versions}")
        print(rows[-1], flush=True)
        time.sleep(1.0)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"\nwritten to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    listed = sys.argv[1:]
    if not listed:
        listed = [
            line.strip()
            for line in (pathlib.Path(__file__).with_name("hosts.txt")).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    main(listed)
