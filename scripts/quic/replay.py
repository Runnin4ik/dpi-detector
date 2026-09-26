"""Replay a captured Initial flight, with and without a retransmission.

The capture shows the endpoint answering a stock client only after it repeats its
Initial (new packet number, same CRYPTO), while the detector - which sends its
flight once - gets a packet no key opens and then silence. This replays the
detector's own captured hello, first as it was sent, then again as a real client
retransmits it, and prints what comes back each time.

Run:  python scripts/quic/replay.py target/validation/quic-discord.pcapng
"""

import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent))
from decrypt import TSHARK, keys_for, parse_long_header, read_varint  # noqa: E402

V1 = 0x00000001
PADDING = 1200


def open_client_packet(packet, dcid):
    """The CRYPTO frame of one client Initial, with the client's own keys."""
    key, iv, hp = keys_for(dcid)[b"client in"]
    _, _, _, _, length, pn_offset = parse_long_header(packet)
    sample = packet[pn_offset + 4:pn_offset + 20]
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_bytes, "big")
    aad = bytes([first]) + packet[1:pn_offset] + pn_bytes
    payload = packet[pn_offset + pn_len:pn_offset + length]
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    plain = AESGCM(key).decrypt(nonce, payload, aad)
    at = 0
    while at < len(plain):
        if plain[at] == 0x06:
            offset, at = read_varint(plain, at + 1)
            chunk, at = read_varint(plain, at)
            return offset, plain[at:at + chunk]
        at += 1
    raise SystemExit("no CRYPTO frame in the captured packet")


def build_initial(dcid, scid, pn, offset, chunk):
    """One client Initial carrying `chunk` at `offset`, sealed and protected."""
    key, iv, hp = keys_for(dcid)[b"client in"]
    body = bytearray()
    body.append(0x06)
    body += varint(offset)
    body += varint(len(chunk))
    body += chunk
    header = bytearray([0xC1])  # long, fixed, Initial, 2-byte packet number (low bits = 1)
    header += V1.to_bytes(4, "big")
    header.append(len(dcid))
    header += dcid
    header.append(len(scid))
    header += scid
    header.append(0)  # token length
    pn_len = 2
    length = pn_len + len(body) + 16
    header += varint(length)
    pn_offset = len(header)
    header += pn.to_bytes(pn_len, "big")
    packet = bytes(header) + AESGCM(key).encrypt(
        bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big"))), bytes(body), bytes(header)
    )
    packet = bytearray(packet)
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(packet[pn_offset + 4:pn_offset + 20])
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]
    if len(packet) < PADDING:
        packet += b"\x00" * (PADDING - len(packet))
    return bytes(packet)


def varint(value):
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    return (value | 0x80000000).to_bytes(4, "big")


def captured_flight(path):
    out = subprocess.run(
        [TSHARK, "-r", path, "-Y", "quic", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "udp.payload"],
        capture_output=True,
        text=True,
    )
    client_packets = []
    server_ip = None
    for line in out.stdout.splitlines():
        if not line.strip():
            continue
        _, src, payload = line.split("\t")
        packet = bytes.fromhex(payload)
        if len(packet) < 20 or packet[0] & 0x80 == 0:
            continue
        _, dcid, scid, _, _, _ = parse_long_header(packet)
        if src.startswith("192.168."):
            client_packets.append((packet, dcid, scid))
        else:
            server_ip = src
    packet, dcid, scid = client_packets[0]
    chunks = [open_client_packet(p, dcid) for p, _, _ in client_packets]
    return dcid, scid, server_ip, chunks


def describe_reply(packet, dcid):
    if len(packet) < 20:
        return f"{len(packet)} bytes (too short)"
    if packet[0] & 0x80 == 0:
        return f"short header, {len(packet)} bytes (1-RTT or a stateless reset)"
    _, pdcid, scid, token, length, pn_offset = parse_long_header(packet)
    shape = f"Initial dcid={pdcid.hex() or '(empty)'} scid={scid.hex()} length={length}"
    key, iv, hp = keys_for(dcid)[b"server in"]
    sample = packet[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return shape + " (no room for a sample)"
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    aad = bytes([first]) + packet[1:pn_offset] + pn_bytes
    payload = packet[pn_offset + pn_len:pn_offset + length]
    nonce = bytes(a ^ b for a, b in zip(iv, int.from_bytes(pn_bytes, "big").to_bytes(12, "big")))
    try:
        plain = AESGCM(key).decrypt(nonce, payload, aad)
    except Exception:  # noqa: BLE001
        return shape + "  -> DOES NOT OPEN with the connection's keys"
    kind = "CRYPTO" if plain[:1] == b"\x06" else ("ACK" if plain[:1] == b"\x02" else f"frame {plain[0]:#04x}")
    handshake = f" handshake_type={plain[5]:#04x}" if plain[:1] == b"\x06" else ""
    return shape + f"  -> OPENED ({kind}{handshake})"


def sweep(path, host, delays):
    """Which delay between the flight and its repeat makes the endpoint answer?"""
    import os
    import socket as socket_module
    import time as time_module

    _, scid, _, chunks = captured_flight(path)
    server_ip = socket_module.getaddrinfo(host, 443, socket_module.AF_INET, socket_module.SOCK_DGRAM)[0][4][0]
    for delay in delays:
        dcid = os.urandom(8)
        sock = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_DGRAM)
        sock.connect((server_ip, 443))
        sock.settimeout(0.5)
        for pn, (offset, chunk) in enumerate(chunks):
            sock.send(build_initial(dcid, scid, pn, offset, chunk))
        replies = []
        end = time_module.time() + delay
        while time_module.time() < end:
            try:
                replies.append(("first flight", sock.recvfrom(4096)[0]))
            except socket_module.timeout:
                continue
        for i, (offset, chunk) in enumerate(chunks):
            sock.send(build_initial(dcid, scid, len(chunks) + i, offset, chunk))
        end = time_module.time() + 3.0
        while time_module.time() < end:
            try:
                replies.append(("retransmit", sock.recvfrom(4096)[0]))
            except socket_module.timeout:
                continue
        sock.close()
        opened = [f"{stage}: {describe_reply(data, dcid)}" for stage, data in replies]
        readable = [line for line in opened if "OPENED" in line]
        print(f"  delay {delay:4.1f}s: {len(replies)} replies, readable: {readable if readable else 'none'}")
        for line in opened:
            print(f"      {line}")


def main(path, host):
    dcid, scid, server_ip, chunks = captured_flight(path)
    # A fresh connection and a fresh address: the captured DCID belongs to a
    # handshake that ended minutes ago (an endpoint has no state for it), and an
    # anycast node the capture saw is not necessarily the one that answers now.
    import os
    import socket as socket_module

    dcid = os.urandom(8)
    server_ip = socket_module.getaddrinfo(host, 443, socket_module.AF_INET, socket_module.SOCK_DGRAM)[0][4][0]
    print(f"replaying the captured hello on a fresh connection: host={host} dcid={dcid.hex()} scid={scid.hex()} server={server_ip}")
    print(f"  chunks={[(o, len(c)) for o, c in chunks]}")

    # Self-check: the rebuilt packet must decrypt back to the same CRYPTO frame.
    rebuilt = build_initial(dcid, scid, 0, *chunks[0])
    offset, chunk = open_client_packet(rebuilt, dcid)
    print(f"  self-check: rebuilt packet decrypts to CRYPTO offset={offset} len={len(chunk)} "
          f"({'matches' if chunk == chunks[0][1] else 'MISMATCH'})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((server_ip, 443))
    sock.settimeout(1.0)

    def drain(seconds, label):
        end = time.time() + seconds
        while time.time() < end:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            print(f"  [{label}] <- {describe_reply(data, dcid)}")

    print("first send (what the detector does: the flight once)")
    for pn, (offset, chunk) in enumerate(chunks):
        sock.send(build_initial(dcid, scid, pn, offset, chunk))
    drain(4.0, "once")

    print("retransmission (what a real client does on PTO: same CRYPTO, new numbers)")
    base = len(chunks)
    for round_number in range(2):
        for i, (offset, chunk) in enumerate(chunks):
            sock.send(build_initial(dcid, scid, base + round_number * len(chunks) + i, offset, chunk))
        drain(1.0, f"retransmit {round_number + 1}")
    drain(4.0, "after retransmissions")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--sweep":
        sweep(
            sys.argv[2] if len(sys.argv) > 2 else "target/validation/quic-discord.pcapng",
            sys.argv[3] if len(sys.argv) > 3 else "discord.com",
            [0.4, 1.0, 2.0, 4.0],
        )
    else:
        main(
            sys.argv[1] if len(sys.argv) > 1 else "target/validation/quic-discord.pcapng",
            sys.argv[2] if len(sys.argv) > 2 else "discord.com",
        )
