"""Dump the transport parameters a client's QUIC ClientHello carries.

The probe's hello is legal but unlike a browser's in a way that matters: RFC 9114
§6.2.1 requires an H3 client to let the server open its unidirectional streams
(`initial_max_streams_uni` of at least 3), and a client that sends no parameters
at all leaves every limit at the RFC's zero default - measured, Cloudflare closes
such a connection with `Error opening control stream`. This reads the real set out
of a capture, so a profile's numbers can come from a client that works.

Run:  python scripts/quic/tp_dump.py target/validation/chrome-quic.pcapng
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decrypt import TSHARK, keys_for, parse_long_header, read_varint  # noqa: E402

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

VERBOSE = "--extensions" in sys.argv

NAMES = {
    0x00: "original_destination_connection_id",
    0x01: "max_idle_timeout",
    0x02: "stateless_reset_token",
    0x03: "max_udp_payload_size",
    0x04: "initial_max_data",
    0x05: "initial_max_stream_data_bidi_local",
    0x06: "initial_max_stream_data_bidi_remote",
    0x07: "initial_max_stream_data_uni",
    0x08: "initial_max_streams_bidi",
    0x09: "initial_max_streams_uni",
    0x0A: "ack_delay_exponent",
    0x0B: "max_ack_delay",
    0x0C: "disable_active_migration",
    0x0D: "preferred_address",
    0x0E: "active_connection_id_limit",
    0x0F: "initial_source_connection_id",
    0x10: "retry_source_connection_id",
}


def open_client(packet, dcid):
    key, iv, hp = keys_for(dcid)[b"client in"]
    _, _, _, _, length, pn_offset = parse_long_header(packet)
    sample = packet[pn_offset + 4:pn_offset + 20]
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    aad = bytes([first]) + packet[1:pn_offset] + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, int.from_bytes(pn_bytes, "big").to_bytes(12, "big")))
    return AESGCM(key).decrypt(nonce, packet[pn_offset + pn_len:pn_offset + length], aad)


def crypto_of(plain):
    """Every CRYPTO frame of one packet, as (offset, data).

    A browser's Initial interleaves PING and PADDING frames with the CRYPTO
    chunks, so the walk has to know each frame's length instead of stopping at
    the first type it does not expect (RFC 9000 §19).
    """
    at = 0
    out = []
    while at < len(plain):
        kind = plain[at]
        if kind == 0x00:  # PADDING
            at += 1
            continue
        if kind == 0x01:  # PING
            at += 1
            continue
        if kind in (0x02, 0x03):  # ACK, ACK+ECN
            at += 1
            _, at = read_varint(plain, at)  # largest acknowledged
            _, at = read_varint(plain, at)  # ack delay
            ranges, at = read_varint(plain, at)
            _, at = read_varint(plain, at)  # first range
            for _ in range(ranges):
                _, at = read_varint(plain, at)
                _, at = read_varint(plain, at)
            if kind == 0x03:
                _, at = read_varint(plain, at)
                _, at = read_varint(plain, at)
                _, at = read_varint(plain, at)
            continue
        if kind == 0x06:  # CRYPTO
            offset, at = read_varint(plain, at + 1)
            chunk, at = read_varint(plain, at)
            out.append((offset, plain[at:at + chunk]))
            at += chunk
            continue
        break
    return out


def assemble(chunks):
    """The stream from offset 0 to the first gap, the way a server reads it."""
    out = b""
    at = 0
    for offset, data in sorted(chunks):
        if offset > at:
            break
        skip = at - offset
        if skip < len(data):
            out += data[skip:]
            at += len(data) - skip
    return out


def extensions(hello):
    """The extension list of a ClientHello, as (type, body) pairs."""
    if len(hello) < 40 or hello[0] != 0x01:
        return []
    at = 4 + 2 + 32
    session_id_len = hello[at]
    at += 1 + session_id_len
    cipher_len = int.from_bytes(hello[at:at + 2], "big")
    at += 2 + cipher_len
    compression_len = hello[at]
    at += 1 + compression_len
    total = int.from_bytes(hello[at:at + 2], "big")
    at += 2
    end = at + total
    out = []
    while at + 4 <= end:
        kind = int.from_bytes(hello[at:at + 2], "big")
        ln = int.from_bytes(hello[at + 2:at + 4], "big")
        out.append((kind, hello[at + 4:at + 4 + ln]))
        at += 4 + ln
    return out


def transport_parameters(body):
    """(id, shown value) for each parameter, values decoded as RFC 9000 varints."""
    at = 0
    out = []
    while at < len(body):
        ident, at = read_varint(body, at)
        ln, at = read_varint(body, at)
        value = body[at:at + ln]
        at += ln
        if ident in (0x00, 0x0F, 0x10, 0x02):
            shown = value.hex() or "(empty)"
        elif value:
            number, consumed = read_varint(value, 0)
            # A value the walk cannot consume whole is not a varint at all: show
            # the bytes rather than a number invented from a prefix.
            shown = str(number) if consumed == len(value) else value.hex()
        else:
            shown = "(empty)"
        out.append((ident, shown))
    return out


def hello_fingerprint(hello):
    """Cipher suites, compression, and the extension list in wire order."""
    if len(hello) < 40:
        return None
    at = 4 + 2 + 32
    session_id_len = hello[at]
    at += 1 + session_id_len
    cipher_len = int.from_bytes(hello[at:at + 2], "big")
    ciphers = [int.from_bytes(hello[at + 2 + i:at + 4 + i], "big") for i in range(0, cipher_len, 2)]
    at += 2 + cipher_len
    compression_len = hello[at]
    compression = list(hello[at + 1:at + 1 + compression_len])
    at += 1 + compression_len
    total = int.from_bytes(hello[at:at + 2], "big")
    at += 2
    end = at + total
    exts = []
    while at + 4 <= end:
        kind = int.from_bytes(hello[at:at + 2], "big")
        ln = int.from_bytes(hello[at + 2:at + 4], "big")
        body = hello[at + 4:at + 4 + ln]
        exts.append((kind, ln, body))
        at += 4 + ln
    return {"ciphers": ciphers, "compression": compression, "extensions": exts, "length": len(hello)}


def print_fingerprint(hello):
    fp = hello_fingerprint(hello)
    if fp is None:
        return
    print(f"  length {fp['length']}  ciphers {[hex(c) for c in fp['ciphers']]}  compression {fp['compression']}")
    print("  order: " + " ".join(f"{kind:#06x}({ln})" for kind, ln, _ in fp["extensions"]))
    for kind, ln, body in fp["extensions"]:
        if kind in (0x000A, 0x000D, 0x0033, 0x002B, 0x0010, 0x002D, 0x44CD, 0xFE0D, 0xCA34, 0x0039):
            shown = body.hex()
            print(f"    {kind:#06x} len={ln:4} {shown[:120]}{'...' if len(shown) > 120 else ''}")


def main(path):
    out = subprocess.run(
        [TSHARK, "-r", path, "-Y", "quic", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "udp.payload"],
        capture_output=True,
        text=True,
    )
    streams = {}
    sources = {}
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        number, src, payload = line.split("\t")
        packet = bytes.fromhex(payload)
        if len(packet) < 40 or packet[0] & 0x80 == 0:
            continue
        try:
            _, dcid, scid, _, _, _ = parse_long_header(packet)
        except IndexError:
            continue
        try:
            plain = open_client(packet, dcid)
        except Exception:  # noqa: BLE001
            continue
        streams.setdefault(dcid, []).extend(crypto_of(plain))
        sources.setdefault(dcid, (number, src))

    for dcid, chunks in streams.items():
        hello = assemble(chunks)
        if len(hello) < 8 or hello[0] != 0x01:
            continue
        number, src = sources[dcid]
        print(f"connection DCID={dcid.hex()} (first packet seen: frame {number} from {src}): ClientHello {len(hello)} bytes")
        if VERBOSE:
            print_fingerprint(hello)
        for kind, body in extensions(hello):
            if kind == 0x39:
                print("  quic_transport_parameters:")
                for ident, shown in transport_parameters(body):
                    print(f"    {NAMES.get(ident, hex(ident)):38} = {shown}")
            elif kind == 0x10:
                print(f"  ALPN: {body.hex()}")
            elif kind == 0x00:
                print(f"  SNI: {body[5:].decode('latin-1', 'replace')}")
            if VERBOSE:
                shown = body.hex()
                print(f"  ext {kind:#06x} len={len(body):4} {shown[:64]}{'...' if len(shown) > 64 else ''}")
        print()


if __name__ == "__main__":
    paths = [a for a in sys.argv[1:] if not a.startswith("--")]
    main(paths[0] if paths else "target/validation/chrome-quic.pcapng")
