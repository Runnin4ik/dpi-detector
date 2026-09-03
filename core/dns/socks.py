"""SOCKS5 UDP-relay (RFC 1928 / RFC 1929) для проксирования DNS-запросов."""

from typing import Optional, Tuple
import asyncio
import struct
import socket
import ipaddress
import time
import logging
from urllib.parse import urlsplit, unquote

from core.dns.wire import _build_dns_query, _parse_dns_response
from core.dns.udp import _SingleQueryProto

logger = logging.getLogger(__name__)


def _parse_socks_proxy(proxy_url: Optional[str]) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    """Разбирает socks5://[user:pass@]host:port → (host, port, user, password)."""
    if not proxy_url:
        return None
    try:
        parsed = urlsplit(proxy_url.strip())
        if parsed.scheme not in ("socks5", "socks5h"):
            return None
        if not parsed.hostname or not parsed.port:
            return None
        if not (1 <= parsed.port <= 65535):
            return None
        user = unquote(parsed.username) if parsed.username is not None else None
        password = unquote(parsed.password) if parsed.password is not None else None
        return (parsed.hostname, parsed.port, user, password)
    except Exception:
        return None


def _unwrap_socks_udp(data: bytes) -> Optional[bytes]:
    """Достаёт payload из SOCKS5 UDP-датаграммы (RSV|FRAG|ATYP|ADDR|PORT|payload)."""
    if len(data) < 4 or data[2] != 0:   # FRAG != 0 — фрагментация не поддержана
        return None
    atyp = data[3]
    off = 4
    try:
        if atyp == 1:
            off += 4
        elif atyp == 3:
            off += 1 + data[off]
        elif atyp == 4:
            off += 16
        else:
            return None
        off += 2
    except IndexError:
        return None
    return data[off:]


class _Socks5UdpRelay:
    """Один UDP DNS-запрос через SOCKS5 UDP-relay (RFC 1928/1929).

    На каждый запрос — свой контрольный TCP-коннект и UDP-сокет до релея:
    просто, без гонок; цена — один лишний RTT на запрос.
    """

    def __init__(self, host: str, port: int, user: Optional[str], password: Optional[str]):
        self._host = host
        self._port = port
        self._user = user
        self._password = password

    async def query(self, addr: str, domain: str, timeout: float,
                    port: int = 53) -> Tuple[Optional[float], object]:
        """Возвращает (elapsed_ms, parsed). При любой ошибке — (None, None)."""
        loop = asyncio.get_running_loop()
        t0 = time.perf_counter()
        writer: Optional[asyncio.StreamWriter] = None
        transport = None
        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
            # ── Greeting: no-auth или user/pass ──
            methods = b"\x00\x02" if self._user else b"\x00"
            writer.write(b"\x05" + bytes([len(methods)]) + methods)
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            if resp[:1] != b"\x05":
                return None, None
            method = resp[1]
            if method == 0xFF:
                return None, None
            if method == 2:
                u = (self._user or "").encode()
                p = (self._password or "").encode()
                writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
                await writer.drain()
                aresp = await asyncio.wait_for(reader.readexactly(2), timeout=10)
                if aresp != b"\x01\x00":
                    return None, None
            # ── UDP ASSOCIATE (0.0.0.0:0) ──
            writer.write(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            if hdr[:2] != b"\x05\x00":
                return None, None
            atyp = hdr[3]
            if atyp == 1:
                relay_host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                ln = (await reader.readexactly(1))[0]
                relay_host = (await reader.readexactly(ln)).decode("utf-8", "replace")
            elif atyp == 4:
                relay_host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                return None, None
            relay_port = struct.unpack(">H", await reader.readexactly(2))[0]
            if relay_host in ("0.0.0.0", "::"):
                relay_host = self._host

            # ── UDP-запрос через релей ──
            q = _build_dns_query(domain)
            tx_id = q[:2]
            fut: asyncio.Future = loop.create_future()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SingleQueryProto(fut), remote_addr=(relay_host, relay_port)
            )
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.version == 4:
                    atyp_and_addr = b"\x01" + socket.inet_aton(addr)
                else:
                    atyp_and_addr = b"\x04" + socket.inet_pton(socket.AF_INET6, addr)
            except ValueError:
                encoded_addr = addr.encode("idna")
                atyp_and_addr = b"\x03" + bytes([len(encoded_addr)]) + encoded_addr
            head = b"\x00\x00\x00" + atyp_and_addr + struct.pack("!H", port)
            transport.sendto(head + q)
            data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
            payload = _unwrap_socks_udp(data)
            if payload is None:
                return None, None
            elapsed_ms = round((t_recv - t0) * 1000, 1)
            return elapsed_ms, _parse_dns_response(payload, tx_id)
        except Exception as e:
            logger.debug("SOCKS5 UDP query error: %s", e, exc_info=True)
            return None, None
        finally:
            if transport:
                transport.close()
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug("Error closing writer: %s", e)
