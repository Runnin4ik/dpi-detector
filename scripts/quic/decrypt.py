"""Decrypt the QUIC Initial packets of a capture by hand (RFC 9001 §5.2/§5.4).

Neither the probe nor tshark could open one class of endpoint reply, so this
derives the Initial keys itself - from the client's DCID, its SCID, the empty
DCID and the server's own SCID - and reports which one opens the packet and what
the plaintext says. That is the difference between "the endpoint sent nothing
readable" and "the endpoint sent a packet under keys the client does not derive".

Run:  python scripts/quic/decrypt.py target/validation/quic-compare.pcapng
"""

import subprocess
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
V1 = 0x00000001


def expand_label(secret, label, length):
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)


def keys_for(dcid):
    # RFC 9001 §5.2: extract with the salt, then HKDF-Expand-Label "client in"
    # and "server in" - the labels are expand labels, not plain HKDF info.
    extract = HMAC(SALT, hashes.SHA256())
    extract.update(dcid)
    initial = extract.finalize()
    out = {}
    for side in (b"client in", b"server in"):
        secret = expand_label(initial, side, 32)
        out[side] = (
            expand_label(secret, b"quic key", 16),
            expand_label(secret, b"quic iv", 12),
            expand_label(secret, b"quic hp", 16),
        )
    return out


def read_varint(buf, at):
    prefix = buf[at] >> 6
    length = 1 << prefix
    value = buf[at] & 0x3F
    for i in range(1, length):
        value = (value << 8) | buf[at + i]
    return value, at + length


def parse_long_header(packet):
    version = int.from_bytes(packet[1:5], "big")
    at = 5
    dcid_len = packet[at]
    at += 1
    dcid = packet[at:at + dcid_len]
    at += dcid_len
    scid_len = packet[at]
    at += 1
    scid = packet[at:at + scid_len]
    at += scid_len
    token_len, at = read_varint(packet, at)
    token = packet[at:at + token_len]
    at += token_len
    length, pn_offset = read_varint(packet, at)
    return version, dcid, scid, token, length, pn_offset


def try_open(packet, dcid, label, side=b"server in"):
    version, pdcid, scid, token, length, pn_offset = parse_long_header(packet)
    if version != V1 or (packet[0] & 0x30) >> 4 != 0:
        print(f"    [{label}] not a v1 Initial (version={version:#010x} type={(packet[0] & 0x30) >> 4})")
        return False
    key, iv, hp = keys_for(dcid)[side]
    sample = packet[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        print(f"    [{label}] no room for a header-protection sample")
        return False
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_bytes, "big")
    aad = bytes([first]) + packet[1:pn_offset] + pn_bytes
    payload = packet[pn_offset + pn_len:pn_offset + length]
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    try:
        plain = AESGCM(key).decrypt(nonce, payload, aad)
    except Exception as error:  # noqa: BLE001
        print(
            f"    [{label}] failed: first={first:#04x} pn_len={pn_len} pn={pn} "
            f"aad={len(aad)} payload={len(payload)} ({type(error).__name__})"
        )
        return False
    print(f"    [{label}] OPENED: pn={pn} plaintext={plain[:80].hex()}")
    describe(plain)
    return True


def describe(plain):
    at = 0
    while at < len(plain):
        frame_type = plain[at]
        if frame_type == 0x00:
            at += 1
            continue
        if frame_type == 0x06:
            offset, at = read_varint(plain, at + 1)
            length, at = read_varint(plain, at)
            kind = plain[at] if length else None
            print(f"      CRYPTO offset={offset} len={length} handshake_type={kind:#04x}" if kind else f"      CRYPTO offset={offset} len={length}")
            at += length
            continue
        if frame_type in (0x1C, 0x1D):
            at += 1
            code, at = read_varint(plain, at)
            alert = f" = TLS alert {code - 0x100}" if 0x100 <= code <= 0x1FF else ""
            print(f"      CONNECTION_CLOSE code={code}{alert}")
            return
        if frame_type == 0x02:
            print("      ACK")
            return
        print(f"      frame type {frame_type:#04x}")
        return


def self_test():
    """RFC 9001 A.1: the key schedule must reproduce the published values."""
    dcid = bytes.fromhex("8394c8f03e515708")
    key, iv, hp = keys_for(dcid)[b"client in"]
    expected = {
        "key": "1f369613dd76d5467730efcbe3b1a22d",
        "iv": "fa044b2f42a3fd3b46fb255c",
        "hp": "9f50449e04a0e810283a1e9933adedd2",
    }
    got = {"key": key.hex(), "iv": iv.hex(), "hp": hp.hex()}
    for name, want in expected.items():
        if got[name] != want:
            print(f"self-test FAILED {name}: got {got[name]} want {want}")
            return False
    print("self-test: the client Initial keys match RFC 9001 A.1")
    return True


def main(path):
    if not self_test():
        return
    out = subprocess.run(
        [TSHARK, "-r", path, "-Y", "quic", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "udp.payload"],
        capture_output=True,
        text=True,
    )
    rows = [line.split("\t") for line in out.stdout.splitlines() if line.strip()]
    packets = []
    for number, src, payload in rows:
        packet = bytes.fromhex(payload)
        if len(packet) < 20 or packet[0] & 0x80 == 0:
            continue
        packets.append((number, src, packet))

    # The client's own CIDs come from its first Initial: the DCID it chose (the
    # key schedule's input) and the SCID it wants answers addressed to.
    client_dcid = client_scid = None
    for number, src, packet in packets:
        if not src.startswith("192.168."):
            continue
        _, dcid, scid, _, _, _ = parse_long_header(packet)
        if client_dcid is None:
            client_dcid, client_scid = dcid, scid
            print(f"client DCID={dcid.hex()} SCID={scid.hex()}")
            break

    candidates = [("client DCID", client_dcid), ("client SCID", client_scid), ("empty DCID", b"")]
    for number, src, packet in packets:
        try:
            _, dcid, scid, token, length, pn_offset = parse_long_header(packet)
        except IndexError:
            continue
        if src.startswith("192.168."):
            # The client's own Initial is the control: its keys are the ones the
            # RFC vector just verified, so if this fails the decryptor is wrong
            # and nothing can be said about the endpoint's packets.
            try_open(packet, client_dcid, f"client frame {number} (control)", side=b"client in")
            continue
        print(
            f"frame {number} from {src}: reply dcid={dcid.hex() or '(empty)'} scid={scid.hex()} "
            f"token={len(token)} length={length} datagram={len(packet)}"
        )
        for label, candidate in candidates + [("server SCID", scid)]:
            if candidate is None:
                continue
            if try_open(packet, candidate, label):
                break
        else:
            print("    no candidate key opened it")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "target/validation/quic-compare.pcapng")
