"""Функции упаковки и распаковки DNS сообщений wire-формата (RFC 1035)."""

from typing import Optional, Union, List
import os
import struct
import socket


def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Собирает DNS-запрос в wire-формате (RFC 1035). qtype: 1=A, 16=TXT.
    Поддерживает IDN/Punycode.
    """
    tx_id = os.urandom(2)
    flags = b'\x01\x00'       # RD=1
    qdcount = b'\x00\x01'
    ancount = nscount = arcount = b'\x00\x00'
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    qname = b''
    for part in domain.strip('.').split('.'):
        if not part:
            continue
        try:
            part_bytes = part.encode('idna')
        except Exception:
            part_bytes = part.encode('ascii', errors='replace')
        if len(part_bytes) > 63:
            part_bytes = part_bytes[:63]
        qname += bytes([len(part_bytes)]) + part_bytes
    qname += b'\x00'

    qtype_bytes = struct.pack('>H', qtype)   # qtype (1=A, 16=TXT, ...)
    qclass = b'\x00\x01'                     # IN
    question = qname + qtype_bytes + qclass
    return header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Пропускает доменное имя в wire-формате (RFC 1035), с защитой от pointer loop."""
    visited = set()
    while offset < len(data):
        if offset in visited:
            return len(data)
        visited.add(offset)
        b = data[offset]
        if b == 0:
            return offset + 1
        if (b & 0xC0) == 0xC0:
            return offset + 2
        offset += b + 1
    return len(data)


def _parse_dns_response(data: bytes, expected_tx_id: bytes) -> Union[List[str], str]:
    """
    Парсит DNS-ответ wire-формата.
    Возвращает список IPv4/IPv6-адресов, "NXDOMAIN", или "PARSE_ERR".
    """
    if len(data) < 12:
        return "PARSE_ERR"
    if data[:2] != expected_tx_id:
        return "PARSE_ERR"

    flags   = struct.unpack(">H", data[2:4])[0]
    rcode   = flags & 0x0F
    ancount = min(struct.unpack(">H", data[6:8])[0], 100)
    if rcode == 3:
        return "NXDOMAIN"
    if rcode != 0 or ancount == 0:
        return "PARSE_ERR"

    # Пропускаем заголовок (12) + вопрос
    offset = _skip_dns_name(data, 12)
    offset += 4  # qtype + qclass
    if offset > len(data):
        return "PARSE_ERR"

    ips = []
    for _ in range(ancount):
        try:
            if offset >= len(data):
                break
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype = struct.unpack(">H", data[offset:offset+2])[0]
            rdlen = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10

            if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):   # A record
                ip = ".".join(str(b) for b in data[offset:offset+4])
                ips.append(ip)
            elif rtype == 28 and rdlen == 16 and offset + 16 <= len(data):  # AAAA record
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                ips.append(ip)
            offset += rdlen
        except (IndexError, struct.error):
            break

    return ips if ips else "PARSE_ERR"


def _parse_txt_response(data: bytes) -> Optional[str]:
    """Извлекает TXT-строку из DNS wire-ответа (тип 16). None — если нет TXT."""
    if len(data) < 12:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    offset = _skip_dns_name(data, 12)
    offset += 4
    if offset > len(data):
        return None

    try:
        for _ in range(ancount):
            if offset >= len(data):
                return None
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype = struct.unpack(">H", data[offset:offset+2])[0]
            rdlen = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen
            if rtype == 16:
                s = b""
                i = 0
                while i < len(rdata):
                    n = rdata[i]
                    s += rdata[i + 1:i + 1 + n]
                    i += 1 + n
                return s.decode("utf-8", "replace")
    except Exception:
        return None
    return None
