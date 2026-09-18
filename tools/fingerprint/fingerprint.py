#!/usr/bin/env python3
"""Compare a `TlsFingerprint` profile against the client it copies.

The Rust harness (`cargo run --example tls_fingerprint`) dumps what *we* send.
This tool is the other half: it drives the `curl-impersonate` bundle that each
profile is transcribed from and diffs the two clients, so a profile can be
re-checked after any change to its data.

Three independent comparisons, weakest to strongest:

  captures   our ClientHello dump against the fork's own reference capture of
             the client (`tests/signatures/*.yaml`) — ciphers, extension list,
             groups, key shares, JA3, JA4. Catches a wrong list or a missing
             extension, but the capture is a third party's sample and says
             nothing about what the bundle sends today.
  echo       both clients against one echo service (`tls.peet.ws/api/all`) —
             JA3/JA4/peetprint, the akamai h2 fingerprint, and every h2 frame
             the service received: SETTINGS payload and order, WINDOW_UPDATE,
             HEADERS priority, pseudo-header order, and the request's headers.
             Measures the shape the far side reads, for both clients alike.
  hello      the bytes each client puts on the wire, captured by a local
             listener with the same SNI on both sides — every extension body,
             the padding length, the compression list, the key shares. Hashes
             drop what this sees: a one-byte difference in a body survives JA3,
             JA4 and peetprint.

A profile is done when `hello` shows no difference but per-connection randomness,
or when every remaining difference is named in `docs/FINGERPRINT_PLAN.md`.

Usage
-----

    python tools/fingerprint/fingerprint.py all [code ...]
    python tools/fingerprint/fingerprint.py hello [code ...]
    python tools/fingerprint/fingerprint.py echo-diff safari18
    python tools/fingerprint/fingerprint.py flags chrome131
    python tools/fingerprint/fingerprint.py captures-fetch

`all` runs every stage for every profile; naming codes limits it to those.
Outputs land in `target/fingerprint/` (bytes, echo reports, captures, dumps) and
are never committed: re-running is cheap, and a stale capture is worse than none.

Options
-------

    --repo DIR       repository root (default: two levels above this file)
    --bundle DIR     curl-impersonate bundle (default: $CURL_IMPERSONATE_DIR,
                     else the newest `curl-impersonate*` in ~/Downloads)
    --work DIR       output directory (default: <repo>/target/fingerprint)
    --target TRIPLE  cargo target triple (default: x86_64-pc-windows-msvc on
                     Windows, else `rustc -vV`'s host)
    --captures DIR   reference capture directory (default: <work>/captures)
    --echo-url URL   echo service (default: https://tls.peet.ws/api/all)
    --no-build       skip `cargo build --profile release-local`
    --show-same      print the fields that agree, not only the differences
    --timeout SEC    per-client timeout (default: 25)

Requires Python 3.8+ with PyYAML for the `captures` stage, the Rust toolchain,
and a bundle directory. Nothing here writes to the repository tree except
`target/`.
"""

import argparse
import glob
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# The profile table: our code name -> the wrapper it reproduces and the fork's
# reference capture of that client. This is the one place the mapping lives; a
# new profile is a line here plus its record in
# `crates/dpi-core/src/net/fingerprint/shapes.rs`.
# ---------------------------------------------------------------------------

PROFILES = [
    ("rustls", None, None),
    ("firefox", "curl_firefox133", "firefox_133.0.3_linux.yaml"),
    ("chrome", "curl_chrome107", "chrome_107.0.5304.107_win10.yaml"),
    ("safari", "curl_safari155", "safari_15.5_macos12.4.yaml"),
    ("chrome133", "curl_chrome133a", "chrome_133.0.6943.55.yaml"),
    ("safari18", "curl_safari180", "safari_18.0_macOS.yaml"),
    ("edge101", "curl_edge101", "edge_101.0.1210.47_win10.yaml"),
    ("chrome99android", "curl_chrome99_android", "chrome_99.0.4844.73_android12-pixel6.yaml"),
    ("chrome120", "curl_chrome120", "chrome_120.0.6099.109_macOS.yaml"),
    ("chrome131", "curl_chrome131", "chrome_131.0.6778.86.yaml"),
    ("chrome131android", "curl_chrome131_android", "chrome_131.0.6778.81_android.yaml"),
    ("chrome136", "curl_chrome136", "chrome_136.0.7103.93.yaml"),
    ("firefox135", "curl_firefox135", "firefox_135.0.1_linux.yaml"),
    ("firefox144", "curl_firefox144", "firefox_144.0.0_linux.yaml"),
    ("safari153", "curl_safari153", "safari_15.3_macos11.6.4.yaml"),
    ("safari184ios", "curl_safari184_ios", "safari_18.4_iOS.yaml"),
    ("safari260", "curl_safari260", "safari_26.0_macOS.yaml"),
    ("safari260ios", "curl_safari260_ios", "safari_26.0_iOS.yaml"),
    ("tor145", "curl_tor145", "tor_14.5_macOS.yaml"),
]

CAPTURE_REPO = "https://github.com/lexiforest/curl-impersonate.git"

EXT_NAMES = {
    0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
    13: "signature_algorithms", 16: "alpn", 18: "sct", 21: "padding", 23: "ems",
    27: "compress_certificate", 28: "record_size_limit", 34: "delegated_credentials",
    35: "session_ticket", 41: "pre_shared_key", 43: "supported_versions",
    45: "psk_key_exchange_modes", 49: "post_handshake_auth", 51: "key_share",
    17513: "alps_old", 17613: "alps", 65037: "ech", 65281: "renegotiation",
}


def log(message):
    print(message, flush=True)


def section(title):
    print(f"\n=== {title}", flush=True)


# ---------------------------------------------------------------------------
# ClientHello: parse and diff
# ---------------------------------------------------------------------------

def is_grease(value):
    return (value & 0x0F0F) == 0x0A0A


def ext_name(kind):
    if is_grease(kind):
        return "GREASE"
    return EXT_NAMES.get(kind, str(kind))


def parse_hello(raw):
    """A TLS ClientHello record, as the fields a comparison reads."""
    body = raw[5:]
    if not body or body[0] != 1:
        raise ValueError(f"not a ClientHello: handshake type {body[0] if body else None}")
    hello = body[4:4 + int.from_bytes(body[1:4], "big")]
    sid_len = hello[34]
    pos = 35 + sid_len
    cipher_len = int.from_bytes(hello[pos:pos + 2], "big")
    ciphers = [int.from_bytes(hello[pos + 2 + i:pos + 4 + i], "big") for i in range(0, cipher_len, 2)]
    pos += 2 + cipher_len
    compression_len = hello[pos]
    compressions = list(hello[pos + 1:pos + 1 + compression_len])
    pos += 1 + compression_len
    end = pos + 2 + int.from_bytes(hello[pos:pos + 2], "big")
    pos += 2
    exts = []
    while pos < end:
        kind = int.from_bytes(hello[pos:pos + 2], "big")
        size = int.from_bytes(hello[pos + 2:pos + 4], "big")
        exts.append((kind, hello[pos + 4:pos + 4 + size]))
        pos += 4 + size
    return {
        "record_version": raw[1:3].hex(),
        "legacy": hello[0:2].hex(),
        "sid_len": sid_len,
        "ciphers": ciphers,
        "compressions": compressions,
        "exts": exts,
        "total": len(raw),
        "hello_len": len(hello),
    }


def masked(values):
    return ["GREASE" if is_grease(v) else v for v in values]


def _read_u16(data, start=0, step=2):
    return [int.from_bytes(data[i:i + 2], "big") for i in range(start, len(data), step)]


def _key_shares(body):
    """(group, key length) pairs, GREASE group names masked."""
    out, pos = [], 2  # the body starts with its own uint16 length
    while pos < len(body):
        group = int.from_bytes(body[pos:pos + 2], "big")
        size = int.from_bytes(body[pos + 2:pos + 4], "big")
        out.append(("GREASE" if is_grease(group) else hex(group), size))
        pos += 4 + size
    return out


def body_diff(kind, mine, theirs):
    """`None` when the two extension bodies match, else what differs."""
    if kind in (0, 5, 18, 23, 35, 65281):
        return None  # no body worth comparing: the name, an empty body, or a ticket
    if kind == 21 or kind == 41:
        return None if len(mine) == len(theirs) else f"length {len(mine)} vs {len(theirs)}"
    if kind == 51:
        return None if _key_shares(mine) == _key_shares(theirs) else \
            f"shares {_key_shares(mine)} vs {_key_shares(theirs)}"
    if kind == 10:
        mine_groups, their_groups = masked(_read_u16(mine, 2)), masked(_read_u16(theirs, 2))
        if [g if g == "GREASE" else hex(g) for g in mine_groups] == \
                [g if g == "GREASE" else hex(g) for g in their_groups]:
            return None
        return f"groups {mine_groups} vs {their_groups}"
    if kind == 43:
        mine_versions = ["GREASE" if is_grease(v) else hex(v) for v in _read_u16(mine, 1)]
        their_versions = ["GREASE" if is_grease(v) else hex(v) for v in _read_u16(theirs, 1)]
        return None if mine_versions == their_versions else f"versions {mine_versions} vs {their_versions}"
    if kind == 13:
        mine_algs, their_algs = _read_u16(mine, 2), _read_u16(theirs, 2)
        return None if mine_algs == their_algs else f"{[hex(a) for a in mine_algs]} vs {[hex(a) for a in their_algs]}"
    return None if mine == theirs else f"{mine.hex()} vs {theirs.hex()}"


def hello_diff(mine, theirs, show_same=False):
    """Every difference between two parsed ClientHellos, as printable lines."""
    lines = []
    for key, label in (("record_version", "record version"), ("legacy", "legacy version")):
        same = mine[key] == theirs[key]
        if same and not show_same:
            continue
        lines.append(f"  {label:16} {'SAME' if same else 'DIFF'}  {mine[key]} vs {theirs[key]}")
    same = mine["sid_len"] == theirs["sid_len"]
    lines.append(f"  {'session id':16} {'SAME' if same else 'DIFF'}  length {mine['sid_len']} vs {theirs['sid_len']}")
    for key, label, values in (("ciphers", "ciphers", masked), ("compressions", "compression", list)):
        same = values(mine[key]) == values(theirs[key])
        if same and not show_same:
            continue
        lines.append(f"  {label:16} {'SAME' if same else 'DIFF'}  "
                     f"{len(mine[key])} vs {len(theirs[key])}")
        if not same:
            lines.append(f"      ours   {values(mine[key])}")
            lines.append(f"      bundle {values(theirs[key])}")
    mine_types = [ext_name(k) for k, _ in mine["exts"]]
    their_types = [ext_name(k) for k, _ in theirs["exts"]]
    same = mine_types == their_types
    lines.append(f"  {'extensions':16} {'SAME' if same else 'DIFF'}  "
                 f"{len(mine_types)} vs {len(their_types)}")
    if not same:
        lines.append(f"      ours   {'-'.join(mine_types)}")
        lines.append(f"      bundle {'-'.join(their_types)}")
    mine_bodies = {k: v for k, v in mine["exts"]}
    their_bodies = {k: v for k, v in theirs["exts"]}
    for kind in sorted(set(mine_bodies) | set(their_bodies), key=lambda k: (is_grease(k), k)):
        if is_grease(kind):
            continue
        if kind not in mine_bodies:
            lines.append(f"  body {ext_name(kind):20} MISSING in ours ({len(their_bodies[kind])} bytes in the bundle)")
            continue
        if kind not in their_bodies:
            lines.append(f"  body {ext_name(kind):20} EXTRA in ours ({len(mine_bodies[kind])} bytes)")
            continue
        diff = body_diff(kind, mine_bodies[kind], their_bodies[kind])
        if diff:
            lines.append(f"  body {ext_name(kind):20} DIFF  {diff}")
    return lines


# ---------------------------------------------------------------------------
# The bundle: wrapper flags, and running a wrapper
# ---------------------------------------------------------------------------

FLAG_WITH_VALUE = re.compile(r"""--(?P<flag>[a-z0-9-]+)(?:[= ](?:"(?P<quoted>[^"]*)"|(?P<bare>[^\s"]+)))?""")


def wrapper_path(bundle, wrapper):
    for name in (wrapper + ".bat", wrapper + ".cmd", wrapper):
        path = os.path.join(bundle, name)
        if os.path.exists(path):
            return path
    return None


def wrapper_flags(bundle, wrapper):
    """The flags and `-H` headers a wrapper names, in the order it names them.

    This is the authoritative reading of what the impersonated client sends: the
    wrapper *is* the client, and every record's h2 shape, header list and TLS
    lists come from here.
    """
    path = wrapper_path(bundle, wrapper)
    if path is None:
        return None
    text = open(path, encoding="utf-8", errors="replace").read()
    flags, headers = {}, []
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"""^-H\s+"([^"]*)"\s*\^?$""", stripped)
        if match:
            name, _, value = match.group(1).partition(":")
            headers.append((name.strip(), value.strip()))
            continue
        for m in FLAG_WITH_VALUE.finditer(stripped):
            flags[m.group("flag")] = m.group("quoted") or m.group("bare") or True
    return {"flags": flags, "headers": headers}


def run_wrapper(bundle, wrapper, url, extra=()):
    """Run a wrapper against `url`, returning (stdout, stderr)."""
    path = wrapper_path(bundle, wrapper)
    if path is None:
        raise SystemExit(f"wrapper {wrapper} not found in {bundle}")
    if os.name == "nt":
        argv = ["cmd", "/c", path, *extra, "-s", "-k", url]
    else:
        argv = [path, *extra, "-s", "-k", url]
    done = subprocess.run(argv, cwd=bundle, capture_output=True)
    return done.stdout.decode("utf-8", "replace"), done.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Harness plumbing: building the example, running it
# ---------------------------------------------------------------------------

class Harness:
    def __init__(self, args):
        self.args = args
        self.repo = os.path.abspath(args.repo or os.path.join(HERE, "..", ".."))
        self.work = os.path.abspath(args.work or os.path.join(self.repo, "target", "fingerprint"))
        self.bundle = args.bundle or default_bundle()
        self.target = args.target or default_target()
        self.captures = args.captures or os.path.join(self.work, "captures")

    def exe(self):
        suffix = ".exe" if os.name == "nt" else ""
        return os.path.join(self.repo, "target", self.target, "release-local", "examples",
                            "tls_fingerprint" + suffix)

    def build(self):
        if self.args.no_build:
            return
        section("build the fingerprint harness")
        argv = ["cargo", "build", "--profile", "release-local", "--example", "tls_fingerprint"]
        if self.target:
            argv += ["--target", self.target]
        done = subprocess.run(argv, cwd=self.repo, capture_output=True)
        sys.stdout.write(done.stdout.decode("utf-8", "replace"))
        sys.stderr.write(done.stderr.decode("utf-8", "replace"))
        if done.returncode != 0:
            raise SystemExit("cargo build failed")

    def example(self, *argv, timeout=None):
        done = subprocess.run([self.exe(), *argv], cwd=self.repo, capture_output=True,
                              timeout=timeout or self.args.timeout * 4)
        return (done.stdout.decode("utf-8", "replace") + done.stderr.decode("utf-8", "replace"))

    def dump(self, code):
        path = os.path.join(self.work, "dump", code + ".txt")
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            text = self.example("dump", code)
            open(path, "w", encoding="utf-8").write(text)
        return open(path, encoding="utf-8").read()


def default_bundle():
    env = os.environ.get("CURL_IMPERSONATE_DIR")
    if env and os.path.isdir(env):
        return env
    pattern = os.path.join(os.path.expanduser("~"), "Downloads", "curl-impersonate*")
    dirs = [p for p in glob.glob(pattern) if os.path.isdir(p)]
    usable = [p for p in dirs if wrapper_path(p, "curl_chrome107")]
    for candidate in reversed(usable or dirs):
        return candidate
    return ""


def default_target():
    if os.name == "nt":
        return "x86_64-pc-windows-msvc"
    done = subprocess.run(["rustc", "-vV"], capture_output=True)
    for line in done.stdout.decode().splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    return ""


def selected(args):
    wanted = args.codes
    for code, wrapper, capture in PROFILES:
        if wanted and code not in wanted:
            continue
        if not wanted and code == "rustls":
            continue  # the baseline impersonates nobody and tunes nothing
        yield code, wrapper, capture


# ---------------------------------------------------------------------------
# Stage: dump — what we send, from the Rust harness
# ---------------------------------------------------------------------------

def stage_dump(harness, args):
    section("dump — our ClientHello, from the Rust harness")
    os.makedirs(os.path.join(harness.work, "dump"), exist_ok=True)
    for code, _, _ in selected(args):
        text = harness.example("dump", code)
        open(os.path.join(harness.work, "dump", code + ".txt"), "w", encoding="utf-8").write(text)
        fields = dict(re.findall(r"^(\w+)\s+= (.*)$", text, re.M))
        log(f"  {code:16} {fields.get('ja4', '?')}")


# ---------------------------------------------------------------------------
# Stage: captures — our dump against the fork's reference capture
# ---------------------------------------------------------------------------

def capture_fetch(harness, ref):
    """Clone or update the fork's reference captures, at the bundle's own tag.

    The captures in `tests/signatures/` are the fork's recordings of the clients
    (and of real browsers); the profile table names one file per profile. The tag
    is derived from the bundle directory name, so a v2.2.2 bundle is compared
    against v2.2.2's captures rather than master's.
    """
    section(f"captures — fetching {CAPTURE_REPO} {ref or '(default branch)'}")
    dest = harness.captures
    if not os.path.isdir(os.path.join(dest, ".git")):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        argv = ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse"]
        if ref:
            argv += ["--branch", ref]
        subprocess.run([*argv, CAPTURE_REPO, dest], capture_output=True)
    elif ref:
        subprocess.run(["git", "-C", dest, "fetch", "--depth", "1", "origin", ref],
                       capture_output=True)
        subprocess.run(["git", "-C", dest, "checkout", "--detach", "FETCH_HEAD"], capture_output=True)
    subprocess.run(["git", "-C", dest, "sparse-checkout", "set", "tests/signatures"],
                   capture_output=True)
    found = glob.glob(os.path.join(dest, "**", "*.yaml"), recursive=True)
    log(f"  {len(found)} captures under {dest}")
    return found


def capture_ref(bundle):
    """`v2.2.2` out of `curl-impersonate-v2.2.2.x86_64-win32`, else None."""
    match = re.search(r"v(\d+\.\d+\.\d+)", os.path.basename(bundle or ""))
    return f"v{match.group(1)}" if match else None


def load_capture(path):
    """One reference capture, in the fields a comparison reads.

    Two capture formats exist in the fork: the v2.2.x tags name an extension
    (`type: server_name`) and give its `SETTINGS` as `{key, value}`, while later
    revisions carry the numeric code and a display name. Both are read here, so
    a bundle can be compared against the captures of its own tag.
    """
    import yaml  # only this stage needs it

    doc = yaml.safe_load(open(path, encoding="utf-8"))
    hello = doc["signature"]["tls_client_hello"]

    def code_of(entry):
        raw = entry.get("type")
        if isinstance(raw, int):
            return raw
        text = str(raw).strip().lower()
        if "grease" in text:
            return None
        if text.isdigit():
            return int(text)
        if text in CAPTURE_EXT_NAMES:
            return CAPTURE_EXT_NAMES[text]
        match = re.search(r"\((\d+)\)", str(entry.get("name", raw)))
        return int(match.group(1)) if match else None

    ciphers = [c for c in hello["ciphersuites"] if isinstance(c, int) and not is_grease(c)]
    exts, groups, shares, sigalgs, point_formats, versions, alpn = [], [], [], [], [], [], []
    for entry in hello["extensions"]:
        kind = code_of(entry)
        exts.append(kind)
        if kind == 10:
            groups = [g for g in entry["supported_groups"] if isinstance(g, int) and not is_grease(g)]
        elif kind == 51:
            shares = [k["group"] for k in entry["key_shares"]
                      if isinstance(k.get("group"), int) and not is_grease(k["group"])]
        elif kind == 13:
            sigalgs = [s for s in entry["sig_hash_algs"] if isinstance(s, int)]
        elif kind == 11:
            point_formats = list(entry.get("ec_point_formats", []))
        elif kind == 43:
            versions = [_version(v) for v in entry["supported_versions"] if v != "GREASE"]
        elif kind == 16:
            alpn = list(entry["alpn_list"])
    frames = doc["signature"]["http2"]["frames"]
    settings = next((f["settings"] for f in frames if f["frame_type"] == "SETTINGS"), [])
    settings = [s if isinstance(s, str) else f"{s['key']}:{s['value']}" for s in settings]
    window = next((f.get("window_size_increment") for f in frames if f["frame_type"] == "WINDOW_UPDATE"), None)
    headers = [h for f in frames if f["frame_type"] == "HEADERS" for h in f.get("headers", [])]
    pseudo = [h for f in frames if f["frame_type"] == "HEADERS" for h in f.get("pseudo_headers", [])]
    if not pseudo:
        pseudo = [h.split(": ", 1)[0] for h in headers if h.startswith(":")]
    shape = {
        "file": os.path.basename(path),
        "browser": f"{doc['browser']['name']} {doc['browser']['version']} {doc['browser']['os']}",
        "ciphers": ciphers,
        "exts": [e for e in exts if e is not None],
        "raw_exts": exts,
        "groups": groups,
        "shares": shares,
        "sigalgs": sigalgs,
        "point_formats": point_formats,
        "versions": versions,
        "alpn": alpn,
        "legacy": _version(hello["record_version"]),
        "h2_settings": settings,
        "h2_window": window,
        "h2_pseudo": pseudo,
        "headers": headers,
    }
    shape["ja3"] = capture_ja3(shape)
    shape["ja4"] = capture_ja4(shape)
    return shape


# The extension names the fork's v2.2.x captures use, and the codes they stand
# for. `application_settings_new` is the 17613 code point Chrome moved to;
# `application_settings` is 17513, the one its older releases sent.
CAPTURE_EXT_NAMES = {
    "server_name": 0,
    "status_request": 5,
    "supported_groups": 10,
    "ec_point_formats": 11,
    "signature_algorithms": 13,
    "application_layer_protocol_negotiation": 16,
    "signed_certificate_timestamp": 18,
    "padding": 21,
    "extended_master_secret": 23,
    "compress_certificate": 27,
    "record_size_limit": 28,
    "delegated_credentials": 34,
    "session_ticket": 35,
    "pre_shared_key": 41,
    "supported_versions": 43,
    "psk_key_exchange_modes": 45,
    "keyshare": 51,
    "key_share": 51,
    "application_settings": 17513,
    "application_settings_old": 17513,
    "application_settings_new": 17613,
    "encrypted_client_hello": 65037,
    "renegotiation_info": 65281,
}

VERSION_NAMES = {
    "TLS_VERSION_1_3": 0x0304,
    "TLS_VERSION_1_2": 0x0303,
    "TLS_VERSION_1_1": 0x0302,
    "TLS_VERSION_1_0": 0x0301,
    "SSL_VERSION_3_0": 0x0300,
}


def _version(value):
    if isinstance(value, int):
        return value
    return VERSION_NAMES.get(str(value), 0)


def _short_hash(text):
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()[:12]


def capture_ja3(shape):
    """JA3 of a capture, the same string our `dump` prints."""
    return "{},{},{},{},{}".format(
        shape["legacy"],
        "-".join(str(c) for c in shape["ciphers"]),
        "-".join(str(e) for e in shape["exts"]),
        "-".join(str(g) for g in shape["groups"]),
        "-".join(str(f) for f in shape["point_formats"]),
    )


def capture_ja4(shape):
    """JA4 of a capture, the same string our `dump` prints."""
    ciphers = [f"{c:04x}" for c in shape["ciphers"]]
    exts = sorted(f"{e:04x}" for e in shape["exts"] if e not in (0, 16))
    ext_input = ",".join(exts)
    if 13 in shape["exts"]:
        ext_input += "_" + ",".join(f"{s:04x}" for s in shape["sigalgs"])
    top = max(shape["versions"]) if shape["versions"] else shape["legacy"]
    version = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}.get(top, "00")
    name = shape["alpn"][0] if shape["alpn"] else ""
    alpn = "00" if not name else (name if len(name) <= 2 else name[0] + name[-1])
    return "t{}{}{:02d}{:02d}{}_{}_{}".format(
        version,
        "d" if 0 in shape["exts"] else "i",
        len(ciphers),
        len(shape["exts"]),
        alpn,
        _short_hash(",".join(sorted(ciphers))),
        _short_hash(ext_input),
    )


def stage_captures(harness, args):
    section("captures — our dump against the fork's reference capture")
    import yaml  # noqa: F401  (fail here, with a clear message, rather than mid-profile)

    root = harness.captures
    if not glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True):
        capture_fetch(harness, args.capture_ref or capture_ref(harness.bundle))
    for code, _, capture in selected(args):
        if not capture:
            continue
        path = os.path.join(root, "tests", "signatures", capture)
        if not os.path.exists(path):
            path = next(iter(glob.glob(os.path.join(root, "**", capture), recursive=True)), None)
        if path is None:
            log(f"  {code:16} capture {capture} not found")
            continue
        shape = load_capture(path)
        mine = dict(re.findall(r"^(\w+)\s+= (.*)$", harness.dump(code), re.M))
        ja3 = mine["ja3"].split(",")
        ciphers, exts = _ints(ja3[1], "-"), _ints(mine["exts"], "-")
        groups, shares = _ints(ja3[3], "-"), _ints(mine["key_share"], ",")
        checks = (
            ("ciphers", ciphers, shape["ciphers"]),
            ("extensions", sorted(exts), sorted(shape["exts"])),
            ("ext order", exts, shape["exts"]),
            ("groups", groups, shape["groups"]),
            ("key shares", shares, shape["shares"]),
            ("ja4", mine["ja4"], shape["ja4"]),
        )
        if args.summary:
            differing = [label for label, ours, theirs in checks if ours != theirs]
            log(f"  {code:16} {'SAME' if not differing else ', '.join(differing)}")
            continue
        log(f"  {code:16} {shape['browser']}  ({shape['file']})")
        for label, ours, theirs in checks:
            if ours == theirs:
                if args.show_same:
                    log(f"      {label:12} SAME ({ours if label in ('ja4',) else len(ours)})")
                continue
            log(f"      {label:12} DIFF ours {ours}")
            log(f"      {'':12}      capt {theirs}")
        ours_exts, capt_exts = set(exts), set(shape["exts"])
        if ours_exts != capt_exts:
            log(f"      only ours    {sorted(ours_exts - capt_exts)}")
            log(f"      only capture {sorted(capt_exts - ours_exts)}")
        log(f"      ja3 legacy   ours {ja3[0]}  capt {shape['legacy']}"
            " (the record version; our dump is the unpinned offer)")
        if shape["h2_settings"] or shape["h2_pseudo"]:
            log(f"      capture h2   {';'.join(shape['h2_settings'])}|{shape['h2_window']}"
                f" pseudo={','.join(h.lstrip(':') for h in shape['h2_pseudo'])}")
        if shape["headers"] and args.show_same:
            for header in shape["headers"]:
                log(f"      capt header  {header}")


def _ints(text, sep):
    return [int(v) for v in str(text).split(sep) if str(v).strip().isdigit()]


# ---------------------------------------------------------------------------
# Stage: echo — both clients against one echo service
# ---------------------------------------------------------------------------

def stage_echo(harness, args):
    section("echo — both clients against the echo service")
    os.makedirs(os.path.join(harness.work, "echo", "ours"), exist_ok=True)
    os.makedirs(os.path.join(harness.work, "echo", "bundle"), exist_ok=True)
    for code, wrapper, _ in selected(args):
        text = harness.example("peet", code)
        open(os.path.join(harness.work, "echo", "ours", code + ".txt"), "w", encoding="utf-8").write(text)
        log(f"  ours   {code:16} {len(text)} bytes")
        if not wrapper:
            continue
        stdout, _ = run_wrapper(harness.bundle, wrapper, args.echo_url)
        open(os.path.join(harness.work, "echo", "bundle", wrapper + ".json"), "w",
             encoding="utf-8").write(stdout)
        log(f"  bundle {wrapper:24} {len(stdout)} bytes"
            f"{'' if stdout.lstrip().startswith('{') else ' (NOT JSON — is the service reachable?)'}")
        time.sleep(0.3)


ECHO_FIELDS = ["tls.ja3", "tls.ja3_hash", "tls.ja4", "tls.peetprint_hash",
               "http2.akamai_fingerprint", "http2.akamai_fingerprint_hash"]


def parse_ours_echo(path):
    fields, frames, headers = {}, [], []
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        match = re.match(r"^\s+(tls\.\S+|http2\.\S+) = (.*)$", line)
        if match:
            fields[match.group(1)] = match.group(2).strip().strip('"')
            continue
        match = re.match(r"^\s+HEADERS (\S+): ?(.*)$", line)
        if match:
            headers.append((match.group(1), match.group(2)))
            continue
        match = re.match(r"^\s+(SETTINGS|WINDOW_UPDATE|HEADERS|PRIORITY|PUSH_PROMISE) (.*)$", line)
        if match and not line.strip().startswith("HEADERS :"):
            frames.append((match.group(1), match.group(2).strip()))
    return {"fields": fields, "frames": frames, "headers": headers}


def parse_bundle_echo(path):
    doc = json.load(open(path, encoding="utf-8"))
    tls, http2 = doc.get("tls", {}), doc.get("http2", {})
    fields = {f"tls.{k}": tls[k] for k in ("ja3", "ja3_hash", "ja4", "peetprint_hash") if k in tls}
    fields.update({f"http2.{k}": http2[k] for k in ("akamai_fingerprint", "akamai_fingerprint_hash")
                   if k in http2})
    frames, headers = [], []
    for frame in http2.get("sent_frames", []):
        shape = frame.get("frame_type", "?")
        if frame.get("settings"):
            shape += " " + ";".join(frame["settings"])
        if frame.get("increment") is not None:
            shape += f" increment {frame['increment']}"
        if frame.get("flags"):
            shape += " " + ",".join(frame["flags"])
        if frame.get("priority"):
            priority = frame["priority"]
            shape += (f" weight {priority.get('weight')} depends_on {priority.get('depends_on')}"
                      f" exclusive {priority.get('exclusive')}")
        frames.append((frame.get("frame_type", "?"), shape.split(" ", 1)[1] if " " in shape else ""))
        for header in frame.get("headers", []):
            name, _, value = header.partition(": ")
            headers.append((name, value))
    return {"fields": fields, "frames": frames, "headers": headers}


def stage_echo_diff(harness, args):
    section("echo-diff — what the service saw, ours against the bundle")
    for code, wrapper, _ in selected(args):
        if not wrapper:
            continue
        ours_path = os.path.join(harness.work, "echo", "ours", code + ".txt")
        theirs_path = os.path.join(harness.work, "echo", "bundle", wrapper + ".json")
        if not os.path.exists(ours_path) or not os.path.exists(theirs_path):
            log(f"  {code:16} no echo report; run the `echo` stage first")
            continue
        ours = parse_ours_echo(ours_path)
        theirs = parse_bundle_echo(theirs_path)
        if args.summary:
            differing = [f for f in ECHO_FIELDS
                         if ours["fields"].get(f) != theirs["fields"].get(f)]
            if ours["frames"] != theirs["frames"]:
                differing.append("h2 frames")
            if ours["headers"] != theirs["headers"]:
                differing.append("headers")
            log(f"  {code:16} {'SAME' if not differing else ', '.join(differing)}")
            continue
        log(f"\n  {code} <- {wrapper}")
        for field in ECHO_FIELDS:
            mine, bund = ours["fields"].get(field), theirs["fields"].get(field)
            if mine == bund and mine is not None:
                if args.show_same:
                    log(f"    {field:30} SAME  {mine}")
                continue
            log(f"    {field:30} DIFF")
            log(f"        ours   {mine}")
            log(f"        bundle {bund}")
        for label, mine, bund in (("h2 frames", ours["frames"], theirs["frames"]),
                                  ("headers", ours["headers"], theirs["headers"])):
            if mine == bund:
                if args.show_same:
                    log(f"    {label:30} SAME  ({len(mine)})")
                continue
            log(f"    {label:30} DIFF")
            log(f"        ours   {mine}")
            log(f"        bundle {bund}")


# ---------------------------------------------------------------------------
# Stage: hello — the bytes each client puts on the wire
# ---------------------------------------------------------------------------

class Listener:
    """One-shot listener on 127.0.0.1:<port>; keeps the first TLS record."""

    def __init__(self, port):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(4)
        self.data = b""
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.sock.settimeout(20)
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(5)
            buf = b""
            while len(buf) < 5:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if len(buf) >= 5:
                need = 5 + struct.unpack_from(">H", buf, 3)[0]
                while len(buf) < need:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                buf = buf[:need]
            self.data = buf
            conn.close()
        except OSError:
            pass
        finally:
            self.done.set()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.done.wait(8)
        try:
            self.sock.close()
        except OSError:
            pass


PORT = 443
SNI = "localhost"


def stage_hello(harness, args):
    section("hello — the bytes each client sends, through one local listener")
    root = os.path.join(harness.work, "bytes")
    os.makedirs(os.path.join(root, "ours"), exist_ok=True)
    os.makedirs(os.path.join(root, "bundle"), exist_ok=True)
    for code, wrapper, _ in selected(args):
        if not wrapper:
            continue
        with Listener(PORT) as listener:
            harness.example("liveany", code, SNI, timeout=60)
            listener.done.wait(8)
        mine = listener.data
        with Listener(PORT) as listener:
            run_wrapper(harness.bundle, wrapper, f"https://{SNI}/",
                        extra=("--connect-to", f"{SNI}:{PORT}:127.0.0.1:{PORT}", "--max-time", "10"))
            listener.done.wait(8)
        theirs = listener.data
        open(os.path.join(root, "ours", code + ".hex"), "w").write(mine.hex())
        open(os.path.join(root, "bundle", wrapper + ".hex"), "w").write(theirs.hex())
        if not mine or not theirs:
            log(f"  {code:16} capture failed (ours {len(mine)}, bundle {len(theirs)} bytes)")
            continue
        log(f"  {code:16} ours {len(mine):5} bytes, bundle {len(theirs):5} bytes")


def stage_hello_diff(harness, args):
    section("hello-diff — captured bytes, ours against the bundle")
    root = os.path.join(harness.work, "bytes")
    for code, wrapper, _ in selected(args):
        if not wrapper:
            continue
        mine_path = os.path.join(root, "ours", code + ".hex")
        theirs_path = os.path.join(root, "bundle", wrapper + ".hex")
        if not os.path.exists(mine_path) or not os.path.exists(theirs_path):
            log(f"  {code:16} no capture; run the `hello` stage first")
            continue
        mine = parse_hello(bytes.fromhex(open(mine_path).read()))
        theirs = parse_hello(bytes.fromhex(open(theirs_path).read()))
        if args.summary:
            labels = []
            for line in hello_diff(mine, theirs):
                text = line.strip()
                if "DIFF" in text or "MISSING" in text or "EXTRA" in text:
                    labels.append(text.split()[0] + " " + text.split()[1])
            log(f"  {code:16} ours {mine['total']:5} B, bundle {theirs['total']:5} B, "
                f"{'SAME' if not labels else '; '.join(labels)}")
            continue
        log(f"\n  {code} <- {wrapper}")
        log(f"    size             ours {mine['total']} bytes / {mine['hello_len']} hello, "
            f"bundle {theirs['total']} / {theirs['hello_len']}")
        for line in hello_diff(mine, theirs, show_same=args.show_same):
            log("  " + line)


# ---------------------------------------------------------------------------
# Stage: flags — what the wrapper itself names
# ---------------------------------------------------------------------------

def stage_flags(harness, args):
    section(f"flags — what each wrapper names (bundle: {harness.bundle})")
    for code, wrapper, _ in selected(args):
        if not wrapper:
            continue
        parsed = wrapper_flags(harness.bundle, wrapper)
        if parsed is None:
            log(f"  {code:16} wrapper {wrapper} not found")
            continue
        flags = parsed["flags"]
        interesting = ["http2-settings", "http2-window-update", "http2-stream-weight",
                       "http2-stream-exclusive", "http2-pseudo-headers-order", "http2-no-priority",
                       "ciphers", "curves", "signature-hashes", "ech", "tlsv1.3", "tlsv1.2", "tlsv1.0",
                       "tls-permute-extensions", "cert-compression", "tls-key-shares-limit",
                       "tls-extension-order", "tls-delegated-credentials", "tls-record-size-limit",
                       "alps", "tls-grease", "tls-signed-cert-timestamps", "no-tls-session-ticket"]
        log(f"\n  {code} <- {wrapper}")
        for name in interesting:
            if name in flags:
                log(f"    --{name:28} {flags[name]}")
        log(f"    headers in wrapper order ({len(parsed['headers'])}):")
        for name, value in parsed["headers"]:
            log(f"      {name}: {value[:80]}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

STAGES = {
    "dump": stage_dump,
    "captures": stage_captures,
    "echo": stage_echo,
    "echo-diff": stage_echo_diff,
    "hello": stage_hello,
    "hello-diff": stage_hello_diff,
    "flags": stage_flags,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("stage", choices=[*STAGES, "all", "captures-fetch", "build"])
    parser.add_argument("codes", nargs="*", help="profile codes; every profile when empty")
    parser.add_argument("--repo")
    parser.add_argument("--bundle")
    parser.add_argument("--work")
    parser.add_argument("--target")
    parser.add_argument("--captures")
    parser.add_argument("--capture-ref", help="fork tag for the reference captures "
                                              "(default: the bundle's own version)")
    parser.add_argument("--echo-url", default="https://tls.peet.ws/api/all")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--show-same", action="store_true")
    parser.add_argument("--summary", action="store_true",
                        help="one line per profile: only which checks differ")
    parser.add_argument("--timeout", type=int, default=25)
    args = parser.parse_args()

    harness = Harness(args)
    if not harness.bundle and args.stage not in ("dump", "captures"):
        log(f"no curl-impersonate bundle found; pass --bundle DIR or set $CURL_IMPERSONATE_DIR")
    if args.stage == "captures-fetch":
        capture_fetch(harness, args.capture_ref or capture_ref(harness.bundle))
        return
    harness.build()
    if args.stage == "build":
        return
    stages = ["dump", "captures", "echo", "echo-diff", "hello", "hello-diff"] if args.stage == "all" \
        else [args.stage]
    for stage in stages:
        STAGES[stage](harness, args)


if __name__ == "__main__":
    main()
