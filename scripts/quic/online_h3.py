"""Does a site serve HTTP/3 at all, independent of our own network?

The column measures the *path from here*; this asks the other question. What a
browser acts on is the *advertisement*: `Alt-Svc` on the HTTPS response, and the
RFC 9460 HTTPS record. A host that names neither is never told to use HTTP/3, and
a QUIC handshake answering is not support. Measured: `gateway.discord.gg` and
`hub.docker.com` answer a handshake and advertise `alpn=h2` only, `x.com` has no
HTTPS record at all — no browser uses HTTP/3 on any of the three, which four
other checkers and a browser agree with. An earlier version of this script read
the answering handshake as support through `intodns.ai` and was wrong, so that
column is gone.

Sources:
  * the host's own advertisement — `Alt-Svc` from a plain HTTPS request, and the
    HTTPS record through a third-party resolver (`cloudflare-dns.com`, DoH JSON;
    no QUIC involved, so a stripped header on our path is not the whole answer);
  * `http3check.net` — LiteSpeed's, which runs the handshake itself and reports
    whether QUIC and HTTP/3 are supported.

A host is `no` only when neither source advertises `h3`. That is what
`quic_unsupported.txt` lists.

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
DOH = "https://cloudflare-dns.com/dns-query?name={}&type=HTTPS"
HTTP3CHECK = "https://http3check.net/?host={}"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) dpi-detector-quic-stand"


def fetch(url, timeout=30, headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


def retrying(url, attempts=4, pause=8.0, headers=None):
    """Third-party APIs rate-limit: back off on 429 rather than reporting a gap."""
    for attempt in range(attempts):
        try:
            return fetch(url, headers=headers)
        except urllib.error.HTTPError as error:
            if error.code == 429 and attempt + 1 < attempts:
                time.sleep(pause * (attempt + 1))
                continue
            return f"ERROR {error.code}"
        except Exception as error:  # noqa: BLE001
            return f"ERROR {type(error).__name__}"
    return "ERROR retries exhausted"


def advertisement(host):
    """What the host tells a browser: `Alt-Svc` on the response, and its HTTPS RR.

    Both are the browser's own inputs, and a host naming neither `h3` is never
    asked for HTTP/3. The record comes from a third-party resolver, so a header
    stripped on our path cannot be the whole answer.
    """
    try:
        request = urllib.request.Request(f"https://{host}/", headers={"User-Agent": UA})
        with urllib.request.urlopen(request, timeout=30) as response:
            alt_svc = response.headers.get("Alt-Svc") or "none"
    except urllib.error.HTTPError as error:
        # A 404 is still an answer, and the headers are what we came for.
        alt_svc = error.headers.get("Alt-Svc") or "none"
    except Exception as error:  # noqa: BLE001
        alt_svc = f"ERROR {type(error).__name__}"

    body = retrying(DOH.format(host), headers={"accept": "application/dns-json"})
    if body.startswith("ERROR"):
        alpn = body
    else:
        try:
            answer = json.loads(body).get("Answer") or []
        except ValueError:
            answer = []
        tokens = sorted({
            token
            for item in answer
            for token in re.findall(r"alpn=([a-z0-9,\-]+)", item.get("data", ""))
        })
        alpn = ",".join(tokens) or "none"

    advertises = "h3" in alt_svc or "h3" in alpn
    return ("yes" if advertises else "no"), f"alt-svc={alt_svc}", f"alpn={alpn}"


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
    rows = [f"{'host':24} {'advertised':11} {'http3check':10} detail"]
    for host in hosts:
        advertised, alt_svc, alpn = advertisement(host)
        time.sleep(1.0)
        check, versions = http3check(host)
        if advertised == "yes" or check == "yes":
            verdict = "yes"
        elif advertised == "no" and check == "no":
            verdict = "no"
        else:
            # One source silent: the host stays probed rather than listed.
            verdict = "unknown"
        rows.append(f"{host:24} {verdict:11} {check:10} {alt_svc} {alpn} | {versions}")
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
