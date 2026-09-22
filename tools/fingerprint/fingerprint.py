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
or when every remaining difference is named in `docs/ADDING_A_PROFILE.md`. `all`
ends with a verdict table: one line per profile, every comparison that ran, and
which of the differences the profile's own wrapper flags account for (a shuffling
shape differs from any single capture in the extension order on every run) —
everything else is printed as `to look at`, because only that named list can say
whether it is expected.

`utls` compares the two libraries directly: each of the uTLS library's own
profiles (dumped through the Go dumper in `tools/fingerprint/utls`) against the
bundle's nearest wrapper, or against one of our own records where the record was
transcribed from that spec (`ours:<code>`). It is not part of `all`, because the
profile stages are the ones that judge a record against the client it copies.

Nine profiles are transcribed from the library's own specs rather than from a
bundle wrapper — the bundle has no wrapper for Chrome 87, 72, 70 and 115 PQ, for
Firefox 120, 105, 99 and 65, or for Go's own client — and `PROFILES` marks those
`utls:HelloX`. For them `hello` and `hello-diff` compare our bytes against the
spec's capture, and the stages that need an HTTP layer (`captures`, `echo`,
`headers`, `flags`) skip them: the library has no HTTP layer to compare, which is
also why their identity is a minimum and their h2 preface is hyper's default.

Usage
-----

    python tools/fingerprint/fingerprint.py all [code ...]
    python tools/fingerprint/fingerprint.py hello [code ...]
    python tools/fingerprint/fingerprint.py echo-diff safari18
    python tools/fingerprint/fingerprint.py flags chrome131
    python tools/fingerprint/fingerprint.py utls
    python tools/fingerprint/fingerprint.py versions
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
import shutil
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
    ("firefox133", "curl_firefox133", "firefox_133.0.3_linux.yaml"),
    ("chrome107", "curl_chrome107", "chrome_107.0.5304.107_win10.yaml"),
    ("safari155", "curl_safari155", "safari_15.5_macos12.4.yaml"),
    ("safari170", "curl_safari170", "safari_17.0_macOS.yaml"),
    ("safari172ios", "curl_safari172_ios", "safari_17.2_iOS.yaml"),
    ("safari180", "curl_safari180", "safari_18.0_macOS.yaml"),
    ("edge101", "curl_edge101", "edge_101.0.1210.47_win10.yaml"),
    ("chrome99android", "curl_chrome99_android", "chrome_99.0.4844.73_android12-pixel6.yaml"),
    ("chrome116", "curl_chrome116", "chrome_116.0.5845.180_win10.yaml"),
    ("chrome123", "curl_chrome123", "chrome_123.0.6312.124.yaml"),
    ("chrome131", "curl_chrome131", "chrome_131.0.6778.86.yaml"),
    ("chrome131android", "curl_chrome131_android", "chrome_131.0.6778.81_android.yaml"),
    # 133-146 send one hello, so the newest wrapper stands for the line and the
    # fork publishes no capture for it — the pin is the wrapper itself.
    ("chrome146", "curl_chrome146", None),
    ("firefox147", "curl_firefox147", "firefox_144.0.0_linux.yaml"),
    ("safari153", "curl_safari153", "safari_15.3_macos11.6.4.yaml"),
    ("safari184ios", "curl_safari184_ios", "safari_18.4_iOS.yaml"),
    ("safari260", "curl_safari260", "safari_26.0_macOS.yaml"),
    ("safari260ios", "curl_safari260_ios", "safari_26.0_iOS.yaml"),
    ("tor145", "curl_tor145", "tor_14.5_macOS.yaml"),
    # Nine shapes the bundle has no wrapper for: the reference is the uTLS
    # library's own spec, captured through the dumper (`utls:HelloX`). Only
    # `hello` applies to these — bytes against bytes — because the library has no
    # HTTP layer, so there is nothing for `echo`, `headers` or `captures` to
    # compare against, and no wrapper flags for the verdict to read.
    ("chrome87", "utls:HelloChrome_87", None),
    ("chrome72", "utls:HelloChrome_72", None),
    ("chrome70", "utls:HelloChrome_70", None),
    ("chrome115pq", "utls:HelloChrome_115_PQ", None),
    ("firefox120", "utls:HelloFirefox_120", None),
    ("firefox105", "utls:HelloFirefox_105", None),
    ("firefox99", "utls:HelloFirefox_99", None),
    ("firefox65", "utls:HelloFirefox_65", None),
    ("go127", "utls:HelloGolang", None),
]

# uTLS's own identifiers against the wrapper that copies the *nearest* client —
# nearest, not equal: the bundle's oldest wrapper stands in for the specs from
# before it, and `HelloFirefox_120` has no wrapper newer than 133 to sit beside.
# A row that differs is not a bug; the table is what says which clients the two
# libraries can express at all, which is the question a tool shipping uTLS has to
# ask of the browsers we copy.
#
# Left out on purpose: the `*_PSK*` specs (the library refuses to build a
# pre-shared-key hello with no session — "empty psk detected"), the
# `HelloRandomized*` specs (the spec itself is drawn from a PRNG, so there is no
# one shape to compare against) and the `*_Auto` aliases (each is the library's
# own newest profile of its family, and `utlsdump list` prints what it resolves
# to). The third field asks the dumper for a real handshake instead of marshalling
# the spec: `HelloGolang` is built by `crypto/tls`, so it needs one.
UTLS_PAIRS = [
    ("HelloChrome_58", "curl_chrome99", False),
    ("HelloChrome_62", "curl_chrome99", False),
    ("HelloChrome_70", "curl_chrome99", False),
    ("HelloChrome_72", "curl_chrome99", False),
    ("HelloChrome_83", "curl_chrome99", False),
    ("HelloChrome_87", "curl_chrome99", False),
    ("HelloChrome_96", "curl_chrome99", False),
    ("HelloChrome_100", "curl_chrome100", False),
    ("HelloChrome_102", "curl_chrome104", False),
    ("HelloChrome_106_Shuffle", "curl_chrome107", False),
    ("HelloChrome_115_PQ", "curl_chrome116", False),
    ("HelloChrome_120", "curl_chrome120", False),
    ("HelloChrome_120_PQ", "curl_chrome120", False),
    ("HelloChrome_131", "curl_chrome131", False),
    ("HelloChrome_133", "curl_chrome133a", False),
    ("HelloEdge_85", "curl_edge99", False),
    ("HelloEdge_106", "curl_edge101", False),
    ("HelloFirefox_55", "curl_firefox133", False),
    ("HelloFirefox_56", "curl_firefox133", False),
    ("HelloFirefox_63", "curl_firefox133", False),
    ("HelloFirefox_65", "curl_firefox133", False),
    ("HelloFirefox_99", "curl_firefox133", False),
    ("HelloFirefox_102", "curl_firefox133", False),
    ("HelloFirefox_105", "curl_firefox133", False),
    ("HelloFirefox_120", "curl_firefox133", False),
    ("HelloSafari_16_0", "curl_safari155", False),
    ("HelloIOS_11_1", "curl_safari172_ios", False),
    ("HelloIOS_12_1", "curl_safari172_ios", False),
    ("HelloIOS_13", "curl_safari172_ios", False),
    ("HelloIOS_14", "curl_safari172_ios", False),
    ("HelloAndroid_11_OkHttp", "curl_chrome99_android", False),
    ("Hello360_7_5", "curl_chrome99", False),
    ("Hello360_11_0", "curl_chrome99", False),
    ("HelloQQ_11_1", "curl_chrome99", False),
    # No browser counterpart at all: the library's own Go client against ours.
    ("HelloGolang", "ours:go127", True),
    # The nine shapes the bundle has no wrapper for. The library's spec is what
    # the record was transcribed from, so this comparison *is* the transcription
    # check: SAME, or a difference the record's own comment names.
    ("HelloChrome_87", "ours:chrome87", False),
    ("HelloChrome_72", "ours:chrome72", False),
    ("HelloChrome_70", "ours:chrome70", False),
    ("HelloChrome_115_PQ", "ours:chrome115pq", False),
    ("HelloFirefox_120", "ours:firefox120", False),
    ("HelloFirefox_105", "ours:firefox105", False),
    ("HelloFirefox_99", "ours:firefox99", False),
    ("HelloFirefox_65", "ours:firefox65", False),
]

CAPTURE_REPO = "https://github.com/lexiforest/curl-impersonate.git"

# `encrypted_client_hello` (RFC 9849 / draft-ietf-tls-esni-18) as a GREASE extension, and the
# payload lengths BoringSSL draws from — four 32-byte-rounded estimates of the inner hello plus
# the AEAD tag (`setup_ech_grease()` in its `ssl/encrypted_client_hello.cc`).
ECH_EXTENSION = 65037
ECH_PAYLOAD_LENGTHS = (144, 176, 208, 240)

# The 512-byte floor's slot (RFC 7685). A shape whose hello can fall under the
# floor draws it per connection, so its *presence* is not a shape difference.
PADDING_EXTENSION = 21

# The labels a padding draw can move, shared by `hello_variation` and the verdict:
# the extension set and order (the slot appears or not), JA4 (which counts it), and
# the echo service's hashes, peetprint among its inputs.
PADDING_LABELS = frozenset({
    "extensions", "ext order", "ja4", "padding", "body padding",
    "tls.ja3", "tls.ja3_hash", "tls.ja4", "tls.ja4_hash", "tls.peetprint_hash",
})

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


def _ech_payload_len(body):
    """The payload length an ECH body declares, or `None` if the header does not decode.

    The body is `type(1) kdf(2) aead(2) config_id(1) enc<2+len> payload<2+len>` and every
    profile here sends an outer hello (type 0) with X25519.
    """
    for off in (1, 0):
        if len(body) < off + 9 or body[off:off + 2] != b"\x00\x01":
            continue
        enc_len = int.from_bytes(body[off + 5:off + 7], "big")
        start = off + 7 + enc_len
        if len(body) >= start + 2:
            return int.from_bytes(body[start:start + 2], "big")
    return None


def _ech_diff(mine, theirs):
    """`None` when both GREASE ECH bodies declare a length a browser picks.

    The payload is random data, so the bytes can never match — but the length can, and it is
    what identifies the build: BoringSSL picks one of four 32-byte-rounded estimates of the
    inner hello and appends the AEAD tag (`setup_ech_grease()` in its
    `ssl/encrypted_client_hello.cc`). Encoding the inner hello this client would really send
    made the payload 400 bytes, a body no browser produces.
    """
    mine_len, their_len = _ech_payload_len(mine), _ech_payload_len(theirs)
    if {mine_len, their_len} <= set(ECH_PAYLOAD_LENGTHS):
        return None  # two independent draws from the same four values
    return f"payloads {mine_len} vs {their_len}, one of {ECH_PAYLOAD_LENGTHS} expected"


def body_diff(kind, mine, theirs):
    """`None` when the two extension bodies match, else what differs."""
    if kind in (0, 5, 18, 23, 35, 65281):
        return None  # no body worth comparing: the name, an empty body, or a ticket
    if kind == ECH_EXTENSION:
        return _ech_diff(mine, theirs)
    if kind in (PADDING_EXTENSION, 41):
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


def hello_labels(mine, theirs):
    """The checks `hello_diff` found, as short labels.

    The extension line is split into `ext order` and `extensions`: a shape whose
    client shuffles its order differs from any single capture on every run even
    when the sets are identical, and telling the two apart is what the verdict
    table needs — `captures` already makes the distinction with its two checks.
    """
    labels = []
    for line in hello_diff(mine, theirs):
        words = line.strip().split()
        if not any(word in ("DIFF", "MISSING", "EXTRA") for word in words):
            continue
        label = " ".join(word for word in words[:2] if word not in ("DIFF", "MISSING", "EXTRA"))
        if label == "extensions":
            mine_types = [ext_name(kind) for kind, _ in mine["exts"]]
            their_types = [ext_name(kind) for kind, _ in theirs["exts"]]
            label = "ext order" if sorted(mine_types) == sorted(their_types) else "extensions"
        labels.append(label)
    return labels


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
        match = re.match(r"""^-H\s+"((?:[^"\\]|\\.)*)"\s*\^?$""", stripped)
        if match:
            raw = match.group(1).replace('\\"', '"')
            name, _, value = raw.partition(":")
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
        differing = []
        for label, ours, theirs in checks:
            if ours == theirs:
                continue
            # A set difference that is the padding slot alone is the 512-byte
            # floor's coin flip, not a shape difference: the fork's capture holds
            # one draw and our dump holds another.
            if label == "extensions" and set(ours) ^ set(theirs) == {PADDING_EXTENSION}:
                label = "padding"
            differing.append(label)
        verdict(code, "captures", differing)
        if args.summary:
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
# Stage: headers — the request block each client sends over HTTP/1.1
# ---------------------------------------------------------------------------

def ensure_cert(harness):
    """A self-signed certificate for the local h1 listener, made once.

    Both clients ignore it (`TlsProfile::insecure`, curl's `-k`): what is being
    compared is the request block, not the certificate.
    """
    cert = os.path.join(harness.work, "tls", "localhost.crt")
    key = os.path.join(harness.work, "tls", "localhost.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    os.makedirs(os.path.dirname(cert), exist_ok=True)
    done = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
         "-keyout", key, "-out", cert, "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost"],
        capture_output=True)
    if done.returncode != 0 or not os.path.exists(cert):
        raise SystemExit("openssl could not make a test certificate:\n"
                         + done.stderr.decode("utf-8", "replace"))
    return cert, key


class Http1Listener:
    """One-shot TLS listener that records the first HTTP/1.1 request block.

    It offers `http/1.1` alone, so the bundle's `--http2` client negotiates h1
    and both sides put the same kind of request on the wire.
    """

    def __init__(self, port, cert, key):
        import ssl

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.context.set_alpn_protocols(["http/1.1"])
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(4)
        self.request = b""
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        self.sock.settimeout(20)
        try:
            conn, _ = self.sock.accept()
            tls = self.context.wrap_socket(conn, server_side=True)
            tls.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.request = data
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            tls.close()
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


def parse_request(raw):
    head = raw.split(b"\r\n\r\n")[0].decode("iso-8859-1")
    lines = head.split("\r\n")
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name, value.strip()))
    return {"line": lines[0], "headers": headers}


def stage_headers(harness, args):
    section("headers — the HTTP/1.1 request block each client sends")
    cert, key = ensure_cert(harness)
    root = os.path.join(harness.work, "headers")
    os.makedirs(os.path.join(root, "ours"), exist_ok=True)
    os.makedirs(os.path.join(root, "bundle"), exist_ok=True)
    for code, wrapper, _ in selected(args):
        if not wrapper or is_utls(wrapper):
            continue
        with Http1Listener(PORT, cert, key) as listener:
            harness.example("headers", code, SNI, timeout=60)
            listener.done.wait(8)
        mine = listener.request
        with Http1Listener(PORT, cert, key) as listener:
            run_wrapper(harness.bundle, wrapper, f"https://{SNI}/",
                        extra=("--connect-to", f"{SNI}:{PORT}:127.0.0.1:{PORT}", "--max-time", "10"))
            listener.done.wait(8)
        theirs = listener.request
        open(os.path.join(root, "ours", code + ".txt"), "wb").write(mine)
        open(os.path.join(root, "bundle", wrapper + ".txt"), "wb").write(theirs)
        if not mine or not theirs:
            log(f"  {code:16} capture failed (ours {len(mine)}, bundle {len(theirs)} bytes)")
            continue
        log(f"  {code:16} ours {len(mine):5} bytes, bundle {len(theirs):5} bytes")


def stage_headers_diff(harness, args):
    section("headers-diff — the request block, ours against the bundle")
    root = os.path.join(harness.work, "headers")
    for code, wrapper, _ in selected(args):
        if not wrapper or is_utls(wrapper):
            continue
        ours_path = os.path.join(root, "ours", code + ".txt")
        theirs_path = os.path.join(root, "bundle", wrapper + ".txt")
        if not os.path.exists(ours_path) or not os.path.exists(theirs_path):
            log(f"  {code:16} no capture; run the `headers` stage first")
            continue
        mine = parse_request(open(ours_path, "rb").read())
        theirs = parse_request(open(theirs_path, "rb").read())
        same_line = mine["line"] == theirs["line"]
        same_case = mine["headers"] == theirs["headers"]
        same_lower = ([(n.lower(), v) for n, v in mine["headers"]]
                      == [(n.lower(), v) for n, v in theirs["headers"]])
        labels = []
        if not same_line:
            labels.append("request line")
        if not same_case:
            labels.append("headers case" if same_lower else "headers")
        verdict(code, "headers-diff", labels)
        if args.summary:
            case_text = "SAME" if same_case else ("case only" if same_lower else "DIFF")
            log(f"  {code:16} {len(mine['headers'])} headers, "
                f"{'request line SAME' if same_line else 'request line DIFF'}, {case_text}")
            continue
        log(f"\n  {code} <- {wrapper}")
        log(f"    request line  {'SAME' if same_line else 'DIFF'}  ours {mine['line']!r}"
            f"  bundle {theirs['line']!r}")
        if same_case:
            log(f"    headers       SAME (names, case and order, {len(mine['headers'])} of them)")
            continue
        if same_lower:
            log(f"    headers       DIFF in name case only (order and values match):")
        else:
            log(f"    headers       DIFF")
        for index in range(max(len(mine["headers"]), len(theirs["headers"]))):
            pair_one = mine["headers"][index] if index < len(mine["headers"]) else None
            pair_two = theirs["headers"][index] if index < len(theirs["headers"]) else None
            if pair_one != pair_two:
                log(f"      [{index}] ours   {pair_one}")
                log(f"      [{index}] bundle {pair_two}")


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
        if not wrapper or is_utls(wrapper):
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
        if not wrapper or is_utls(wrapper):
            continue
        ours_path = os.path.join(harness.work, "echo", "ours", code + ".txt")
        theirs_path = os.path.join(harness.work, "echo", "bundle", wrapper + ".json")
        if not os.path.exists(ours_path) or not os.path.exists(theirs_path):
            log(f"  {code:16} no echo report; run the `echo` stage first")
            continue
        ours = parse_ours_echo(ours_path)
        theirs = parse_bundle_echo(theirs_path)
        differing = [f for f in ECHO_FIELDS if ours["fields"].get(f) != theirs["fields"].get(f)]
        if ours["frames"] != theirs["frames"]:
            differing.append("h2 frames")
        if ours["headers"] != theirs["headers"]:
            differing.append("headers")
        verdict(code, "echo-diff", differing)
        if args.summary:
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
        # A `utls:` reference is a spec the dumper captures; a bundle wrapper is
        # run against the same listener. Either way the comparison is bytes
        # against bytes — the only one the library's profiles support, because it
        # has no HTTP layer for `echo` or `headers` to compare.
        theirs_path = counterpart_capture(harness, wrapper, args)
        theirs = read_hex(theirs_path) if theirs_path else b""
        open(os.path.join(root, "ours", code + ".hex"), "w").write(mine.hex())
        open(os.path.join(root, "bundle", reference_name(wrapper) + ".hex"), "w").write(theirs.hex())
        if not mine or not theirs:
            log(f"  {code:16} capture failed (ours {len(mine)}, bundle {len(theirs)} bytes)")
            continue
        log(f"  {code:16} ours {len(mine):5} bytes, bundle {len(theirs):5} bytes")


def stage_hello_diff(harness, args):
    section("hello-diff — captured bytes, ours against the reference client")
    root = os.path.join(harness.work, "bytes")
    for code, wrapper, _ in selected(args):
        if not wrapper:
            continue
        mine_path = os.path.join(root, "ours", code + ".hex")
        theirs_path = os.path.join(root, "bundle", reference_name(wrapper) + ".hex")
        if not os.path.exists(mine_path) or not os.path.exists(theirs_path):
            log(f"  {code:16} no capture; run the `hello` stage first")
            continue
        mine = parse_hello(bytes.fromhex(open(mine_path).read()))
        theirs = parse_hello(bytes.fromhex(open(theirs_path).read()))
        labels = hello_labels(mine, theirs)
        verdict(code, "hello-diff", labels)
        if args.summary:
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
        if not wrapper or is_utls(wrapper):
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
# Stage: utls — the library's own profiles against the wrapper beside them
# ---------------------------------------------------------------------------

def utls_dumper(harness, args, required=True):
    """The Go dumper from `tools/fingerprint/utls`, built into the work directory."""
    root = os.path.join(harness.work, "utls")
    os.makedirs(root, exist_ok=True)
    exe = os.path.join(root, "utlsdump" + (".exe" if os.name == "nt" else ""))
    if args.no_build and os.path.exists(exe):
        return exe
    go = shutil.which("go")
    if go is None:
        if not required:
            return None
        raise SystemExit("the `utls` stage builds tools/fingerprint/utls, so it needs the Go "
                         "toolchain on PATH")
    done = subprocess.run([go, "build", "-o", exe, "."], cwd=os.path.join(HERE, "utls"),
                          capture_output=True)
    if done.returncode != 0 or not os.path.exists(exe):
        raise SystemExit("go build failed:\n" + done.stderr.decode("utf-8", "replace"))
    return exe


def utls_version():
    """The uTLS release the dumper pins, out of its own `go.mod`."""
    path = os.path.join(HERE, "utls", "go.mod")
    for line in open(path, encoding="utf-8"):
        if "refraction-networking/utls" in line:
            return line.split()[-1]
    return "uTLS"


def is_utls(wrapper):
    """True when a profile's reference is a uTLS spec rather than a bundle wrapper."""
    return bool(wrapper) and wrapper.startswith("utls:")


def read_hex(path):
    """The bytes in a capture file: pure hex, or hex with `#` comments and row breaks.

    Our own captures are written by the listener as one hex string; a uTLS
    capture comes from the dumper, which prints a `#` header line and 32-byte
    rows. Both are the same record, so one reader takes both.
    """
    text = open(path).read()
    digits = "".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", digits))


def reference_name(wrapper):
    """The reference's name as a file stem: `utls:HelloX` has no colon on disk."""
    return wrapper.replace(":", "_")


def counterpart_capture(harness, counterpart, args):
    """The reference client's hello, fresh each run.

    `counterpart` is a bundle wrapper name, `ours:<code>` for one of our own
    profiles, or `utls:<HelloX>` for a spec the dumper captures — the last needs
    the Go toolchain, which `utls_dumper` builds once per run. Nothing here is
    cached: a stale capture is worse than none, and every one of these is cheap.
    """
    root = os.path.join(harness.work, "utls")
    os.makedirs(root, exist_ok=True)
    if counterpart.startswith("utls:"):
        spec = counterpart.split(":", 1)[1]
        path = os.path.join(root, spec + ".hex")
        argv = [utls_dumper(harness, args), "dump", spec, "-sni", SNI, "-o", path]
        if spec in HANDSHAKE_SPECS:
            argv.append("-handshake")
        done = subprocess.run(argv, capture_output=True)
        if done.returncode != 0 or not os.path.exists(path):
            log(f"  {spec}: {done.stderr.decode('utf-8', 'replace').strip()}")
            return None
        return path
    if counterpart.startswith("ours:"):
        code = counterpart.split(":", 1)[1]
        path = os.path.join(root, "ours_" + code + ".hex")
        with Listener(PORT) as listener:
            harness.example("liveany", code, SNI, timeout=60)
            listener.done.wait(8)
    else:
        path = os.path.join(root, "bundle_" + counterpart + ".hex")
        with Listener(PORT) as listener:
            run_wrapper(harness.bundle, counterpart, f"https://{SNI}/",
                        extra=("--connect-to", f"{SNI}:{PORT}:127.0.0.1:{PORT}", "--max-time", "10"))
            listener.done.wait(8)
    if len(listener.data) < 6:
        return None
    open(path, "w").write(listener.data.hex())
    return path


# The labels a difference between two clients can carry and still be the same
# shape: an order the client shuffles per connection, and the two slots it draws
# per connection (the 512-byte padding floor, the GREASE ECH payload length).
DRAW_LABELS = {
    "ext order",
    "extensions",
    "body 21 (padding)",
    "body 65037 (encrypted_client_hello)",
}


def pair_kind(labels):
    """What a difference between two clients is, judged by the labels `diff` printed."""
    if labels == "SAME":
        return "identical"
    parts = set(labels.split(", "))
    if parts == {"ext order"}:
        return "the extension order"
    if parts <= DRAW_LABELS and parts & {"body 21 (padding)", "body 65037 (encrypted_client_hello)"}:
        return "a per-connection draw"
    return "shape"


def stage_utls(harness, args):
    section("utls — the library's own profiles against the wrapper that copies the same client")
    dumper = utls_dumper(harness, args)
    root = os.path.join(harness.work, "utls")
    counts, missing = {}, []
    for spec, counterpart, handshake in UTLS_PAIRS:
        mine = os.path.join(root, spec + (".handshake" if handshake else "") + ".hex")
        if not os.path.exists(mine):
            argv = [dumper, "dump", spec, "-sni", SNI, "-o", mine]
            done = subprocess.run(argv + (["-handshake"] if handshake else []), capture_output=True)
            if done.returncode != 0:
                log(f"  {spec:32} {done.stderr.decode('utf-8', 'replace').strip()}")
                missing.append(spec)
                continue
        theirs = counterpart_capture(harness, counterpart, args)
        if theirs is None:
            log(f"  {spec:32} no capture for {counterpart}")
            missing.append(spec)
            continue
        text = harness.example("diff", mine, theirs)
        labels = "?"
        for line in text.splitlines():
            if line.startswith("result"):
                labels = line.split("=", 1)[1].strip()
        # `3 difference(s): a, b` and `SAME` — the labels are what follows the colon.
        if ": " in labels:
            labels = labels.split(": ", 1)[1]
        kind = pair_kind(labels)
        counts[kind] = counts.get(kind, 0) + 1
        log(f"  {spec:32} vs {counterpart:20} {labels:44} {kind}")
        if not args.summary and labels != "SAME":
            for line in text.splitlines():
                if line.startswith("  ") and "DIFF" in line:
                    log("    " + line.strip())
    total = ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items()))
    log(f"\n  {len(UTLS_PAIRS)} pairs: {total}")
    if missing:
        log(f"  not captured: {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Stage: versions — every wrapper in the bundle, by hash and by what moves
# ---------------------------------------------------------------------------

# How many times each wrapper is run. Ten draws is what it takes to see a
# one-in-four slot twice with the odds in our favour (1 - (3/4)^10 is 94%) and to
# tell a shuffling order from a fixed one, which two draws already settle.
VERSION_DRAWS = 10


def wrapper_names(bundle):
    """Every `curl_*` wrapper in the bundle, by name."""
    return sorted(os.path.splitext(os.path.basename(path))[0]
                  for path in glob.glob(os.path.join(bundle, "curl_*")))


# The specs whose hello `crypto/tls` builds, so the dumper has to take them off a
# real handshake instead of marshalling the spec. Shared with the pair table.
HANDSHAKE_SPECS = {spec for spec, _, handshake in UTLS_PAIRS if handshake}


def report_version(name, draws, args):
    """One client's line: its JA4 (both, when it draws two) and what moves."""
    ja4 = sorted({draw["ja4"] for draw in draws})
    ja3 = {draw["ja3"] for draw in draws}
    sizes = sorted({int(draw["record"].split()[0]) for draw in draws})
    sets = {tuple(sorted(draw["exts"].split("-"))) for draw in draws}
    moves = []
    if len(ja3) > 1:
        moves.append(f"JA3 x{len(ja3)}")
    if len(ja4) > 1:
        moves.append(f"JA4 x{len(ja4)}")
    if len(sizes) > 1:
        moves.append("size " + "/".join(str(size) for size in sizes))
    if len(sets) > 1:
        moves.append("padding coin")
    log(f"  {name:26} {ja4[0]:44} {'; '.join(moves) if moves else 'stable'}")
    for extra in ja4[1:]:
        log(f"  {'':26} {extra}")
    if not args.summary:
        first = draws[0]
        log(f"  {'':26} ciphers {len(first['ja3'].split(',')[1].split('-'))}, "
            f"exts {len(first['exts'].split('-'))}, key shares {first['key_share']}")
    return {
        "ja4": ja4,
        "ja3_variants": len(ja3),
        "ext_sets": len(sets),
        "sizes": sizes,
        "key_share": draws[0]["key_share"],
        "ciphers": len(draws[0]["ja3"].split(",")[1].split("-")),
        "exts": len(draws[0]["exts"].split("-")),
    }


def print_ja4_groups(collected):
    """Which clients share a JA4 — and a block on one hash takes all of them.

    This is the note a matcher needs: JA4 is what a middlebox can pin when JA3 is
    permuted per connection, so the members of one group fall together, whatever
    their version, their PQ key share or their extension order. A client that
    draws two hashes is listed under both, and that is the padding coin — a block
    on one of them drops only the connections that draw it.

    The `HelloRandomized*` specs are left out: their hash is new on every
    connection, so they are in no group by construction.
    """
    groups = {}
    for name, summary in collected.items():
        if name.startswith("HelloRandomized"):
            continue
        for ja4 in summary["ja4"]:
            groups.setdefault(ja4, []).append(name)
    log(f"\n  --- by JA4: {len(groups)} hashes over "
        f"{sum(1 for name in collected if not name.startswith('HelloRandomized'))} clients")
    for ja4, members in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0])):
        members.sort()
        log(f"  {ja4:44} {len(members):2}  {', '.join(members)}")
        shares = sorted({collected[name]["key_share"] for name in members})
        shuffling = sum(1 for name in members if collected[name]["ja3_variants"] > 1)
        extra = []
        if len(shares) > 1:
            extra.append("key shares " + " / ".join(shares))
        if shuffling:
            extra.append(f"{shuffling} permute the order")
        if len({collected[name]["exts"] for name in members}) > 1:
            extra.append("extension counts " +
                         "/".join(str(n) for n in sorted({collected[name]["exts"]
                                                          for name in members})))
        if extra:
            log(f"  {'':44}     {'; '.join(extra)}")


def stage_versions(harness, args):
    """What each version sends, and which of its hashes move.

    Not "is our profile right" but "what can a middlebox pin at all": a Chromium
    from 110 on permutes its extension order on every connection, so its JA3 is
    never twice the same and only JA4 can be pinned — while Firefox and Safari do
    not permute, and the ones whose hello falls near the 512-byte floor take a
    second JA4 whenever the GREASE ECH payload draw leaves them room to pad.

    Two ladders, because neither source covers the other: the bundle goes back to
    Chrome 99, Firefox 133 and Safari 15.3, and the uTLS library back to Chrome 58,
    Firefox 55 and iOS 11 — and stops at Chrome 133, Firefox 120, Safari 16.0.
    Where they overlap the behaviour agrees, which is the point of printing both.
    """
    section("versions — every client the two sources ship, by what it sends and what moves")
    root = os.path.join(harness.work, "versions")
    os.makedirs(root, exist_ok=True)
    collected = {}
    for wrapper in wrapper_names(harness.bundle):
        draws = []
        for index in range(VERSION_DRAWS):
            path = os.path.join(root, f"{wrapper}-{index}.hex")
            if not os.path.exists(path) or os.path.getsize(path) < 12:
                with Listener(PORT) as listener:
                    run_wrapper(harness.bundle, wrapper, f"https://{SNI}/",
                                extra=("--connect-to", f"{SNI}:{PORT}:127.0.0.1:{PORT}",
                                       "--max-time", "10"))
                    listener.done.wait(8)
                open(path, "w").write(listener.data.hex())
            fields = dict(re.findall(r"^(\w+)\s+= (.*)$", harness.example("hello", path), re.M))
            if "ja4" in fields:
                draws.append(fields)
        if draws:
            collected[wrapper] = report_version(wrapper, draws, args)
        else:
            log(f"  {wrapper:26} no capture")

    dumper = utls_dumper(harness, args, required=False)
    if dumper is None:
        log("\n  uTLS ladder skipped: no Go toolchain on PATH")
        print_ja4_groups(collected)
        return
    specs = [line.split()[0] for line in
             subprocess.run([dumper, "list"], capture_output=True).stdout.decode().splitlines()
             if line.strip()]
    root = os.path.join(harness.work, "utls-ladder")
    os.makedirs(root, exist_ok=True)
    refused = []
    log(f"\n  --- uTLS {utls_version()} ({len(specs)} profiles)")
    for spec in specs:
        draws = []
        for index in range(VERSION_DRAWS):
            path = os.path.join(root, f"{spec}-{index}.hex")
            if not os.path.exists(path) or os.path.getsize(path) < 100:
                argv = [dumper, "dump", spec, "-sni", SNI, "-o", path]
                if spec in HANDSHAKE_SPECS:
                    argv.append("-handshake")
                done = subprocess.run(argv, capture_output=True)
                if done.returncode != 0:
                    refused.append(spec)
                    break
            fields = dict(re.findall(r"^(\w+)\s+= (.*)$", harness.example("hello", path), re.M))
            if "ja4" in fields:
                draws.append(fields)
        if draws:
            collected[spec] = report_version(spec, draws, args)
        elif spec not in refused:
            log(f"  {spec:26} no capture")
    if refused:
        log(f"\n  not captured ({len(refused)}): {', '.join(refused)}")
        log("  the library builds a pre-shared-key hello only with a session (\"empty psk detected\")")
    print_ja4_groups(collected)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# The verdict: every profile, every comparison, one line each
# ---------------------------------------------------------------------------

VERDICTS = {}

# How many times a profile's own hello is drawn before the verdict judges whether
# it varies at all. The padding floor flips one connection in four, so a handful of
# draws is not enough: at 24 the chance of missing it is (3/4)^24, about 0.1%.
SAMPLES = 24


def verdict(code, stage, labels):
    """Records one profile's outcome for the closing table."""
    VERDICTS.setdefault(code, {})[stage] = ", ".join(labels) if labels else "SAME"


def hello_variation(harness, code):
    """Which labels the profile's own hello already varies in, across draws.

    Measured, not declared: the bundle names `--tls-permute-extensions` from
    `curl_chrome123` on while the fork's captures mark every Chromium from 110 up,
    so the flag alone would miss `chrome116` — and the two shapes that can fall
    under the 512-byte padding floor draw a padding slot on one connection in
    four. An extension *order* that moves is a shuffling shape; a *set* that moves
    is the padding coin flip, which moves the order with it. JA3 follows both,
    JA4 and peetprint follow the padding.
    """
    def draw():
        text = harness.example("dump", code)
        exts = re.search(r"^exts\s+= (.*)$", text, re.M)
        size = re.search(r"^record\s+= (\d+) bytes$", text, re.M)
        return (exts.group(1) if exts else None, size.group(1) if size else None)

    draws = {draw() for _ in range(SAMPLES)}
    if len(draws) < 2 or any(exts is None for exts, _ in draws):
        return set(), []
    orders = {tuple(exts.split("-")) for exts, _ in draws}
    sets = {tuple(sorted(exts.split("-"))) for exts, _ in draws}
    if len(sets) > 1:
        return set(PADDING_LABELS), ["its own hello varies (padding)"]
    if len(orders) > 1:
        return {"ext order", "tls.ja3", "tls.ja3_hash"}, ["its own hello varies (order)"]
    return set(), []


# Differences a record's own comment names as deliberate, so a run does not report
# a documented deviation as something to look at. The authority stays the record's
# comment and `docs/ADDING_A_PROFILE.md`; this is the machine's copy of the same
# fact, and the reason is printed beside the row. The two vocabularies differ —
# the Rust `diff` prints `body 51 (key_share)` and
# `body 65037 (encrypted_client_hello)`, the Python `hello_diff` prints
# `body key_share` and `body ech` — so both spellings are listed.
EXCUSED = {
    "chrome115pq": (
        {"body key_share", "body 51 (key_share)", "key shares"},
        "the draft hybrid group is advertised but not shared: no provider carries it",
    ),
    "firefox120": (
        {"body ech", "body 65037 (encrypted_client_hello)"},
        "the reference pins the ECH payload length, we draw it",
    ),
}


def expectations(harness, code, wrapper):
    """The differences this profile's own client explains, and why.

    Three sources, all about the client or the record rather than about the
    measurement: a measured pair of its own hellos (`hello_variation`), its
    wrapper's flags (a key-share limit belongs to the wrapper, not to the
    browser), and the deviations its own comment names ([`EXCUSED`]). The named
    differences in `tools/fingerprint/README.md` remain the list a reader checks
    everything else against.
    """
    explained, why = hello_variation(harness, code)
    if code in EXCUSED:
        labels, reason = EXCUSED[code]
        explained |= labels
        why.append(reason)
    # A `padding` label anywhere is the same coin flip seen once: eight draws can
    # miss a one-in-four slot, while the comparison against the fork's single
    # capture cannot. The reason is printed, so a reader can tell what was
    # explained rather than take it on faith.
    if any("padding" in outcome for outcome in VERDICTS.get(code, {}).values()):
        explained |= PADDING_LABELS
        why.append("the padding slot is a per-connection draw")
    flags = (wrapper_flags(harness.bundle, wrapper) or {}).get("flags", {}) if wrapper else {}
    if "tls-key-shares-limit" in flags:
        explained |= {"key shares"}
        why.append("its wrapper limits the key shares")
    return explained, why


def print_verdicts(harness, args):
    """The closing table: what each comparison found, and what that means.

    A difference is explained when the profile's own client accounts for it, and
    the reason is printed beside it; everything else is listed as `to look at`,
    because only the named list in the README can say whether it is expected.
    """
    if not VERDICTS:
        return
    section("verdict — every profile, every comparison")
    stages = [stage for stage in ("captures", "echo-diff", "headers-diff", "hello-diff")
              if any(stage in row for row in VERDICTS.values())]
    clean, explained_count, unexplained = 0, 0, []
    for code, wrapper, _ in selected(args):
        row = VERDICTS.get(code)
        if row is None:
            continue
        differing = {stage: row[stage] for stage in stages if row.get(stage) not in (None, "SAME")}
        if not differing:
            clean += 1
            log(f"  {code:16} SAME in every comparison")
            continue
        # Only a profile that differs is worth drawing 24 times: a clean one has
        # nothing to explain.
        explained, why = expectations(harness, code, wrapper)
        parts, loose = [], []
        for stage, outcome in differing.items():
            labels = outcome.split(", ")
            mine = [label for label in labels if label not in explained]
            loose += [f"{stage}: {label}" for label in mine]
            parts.append(f"{stage}={outcome}" + ("" if mine else f" ({'; '.join(why)})"))
        if loose:
            unexplained.append(code)
            log(f"  {code:16} " + "; ".join(parts))
            log(f"  {'':16} to look at: {', '.join(loose)}")
        else:
            explained_count += 1
            log(f"  {code:16} " + "; ".join(parts))
    log(f"\n  {len(VERDICTS)} profiles: {clean} clean, {explained_count} explained by their own client, "
        f"{len(unexplained)} to look at")
    log("  named differences are listed in tools/fingerprint/README.md; anything else is a bug in the record")


STAGES = {
    "dump": stage_dump,
    "captures": stage_captures,
    "echo": stage_echo,
    "echo-diff": stage_echo_diff,
    "headers": stage_headers,
    "headers-diff": stage_headers_diff,
    "hello": stage_hello,
    "hello-diff": stage_hello_diff,
    "flags": stage_flags,
    "utls": stage_utls,
    "versions": stage_versions,
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
    stages = ["dump", "captures", "echo", "echo-diff", "headers", "headers-diff",
              "hello", "hello-diff"] if args.stage == "all" else [args.stage]
    for stage in stages:
        STAGES[stage](harness, args)
    if args.stage == "all":
        print_verdicts(harness, args)


if __name__ == "__main__":
    main()
