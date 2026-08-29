from __future__ import annotations

import os
import re
import json
import struct
import tempfile
import socket
import asyncio
import base64
import time
import ssl
from typing import Tuple, List, Union, Optional
import httpx
from utils import config
from cli.console import console
from utils.network import get_fake_ip_type, pin_host, get_resolved_ip, is_ip_literal
from utils.error_classifier import classify_connect_error, classify_read_error

# ── Белый список известных резолверов ────────────────────────────────────────
# Если UDP-запрос к серверу фактически обработал резолвер из этого списка
# (выходной IP, /24 совпадает с сетью известного публичного DNS) — это подмена
# на известный резолвер, а не перехват ТСПУ: показываем зелёным, не красным.
# MSK-IX/НСДИ не включаем — отечественные, судятся отдельно как _is_domestic.


# Белый список серверов по имени (подстроки, регистр не важен): если заявленный
# DNS-сервер называется, например, "Google", его выход не считается перехватом.
# Список вынесен в config.yml (DNS_KNOWN_RESOLVER_NAMES).
# Белый список резолверов по имени — весь в config.yml (DNS_KNOWN_RESOLVER_NAMES).
_KNOWN_RESOLVER_NAME_TOKENS: set = set(
    getattr(config, "DNS_KNOWN_RESOLVER_NAMES", [])
)


def _known_resolver(name: str) -> bool:
    """Выходной резолвер — известный публичный DNS по имени сервера из конфига."""
    return bool(name) and any(tok in name.lower() for tok in _KNOWN_RESOLVER_NAME_TOKENS)


# ── Ручной порядок провайдеров в DNS-тесте ──────────────────────────────────
# Сначала популярные (google → cloudflare → quad9 → adguard), потом остальные
# по алфавиту, в конце — российские (xbox → comss → yandex → geohide → msk-ix
# → нсди).
_DNS_ORDER_POPULAR = ("google", "cloudflare", "quad9", "adguard")
_DNS_ORDER_RU = ("xbox", "comss", "yandex", "geohide", "msk", "нсди")


def _dns_name_sort_key(name: str) -> tuple:
    """Ключ сортировки имени провайдера: (тир, позиция в тире, имя).

    Тир 0 — популярные, тир 1 — остальные (алфавит), тир 2 — российские
    в самом конце списка.
    """
    low = name.lower()
    for i, prefix in enumerate(_DNS_ORDER_POPULAR):
        if low.startswith(prefix):
            return (0, i, low)
    if any(low.startswith(p) for p in _DNS_ORDER_RU):
        i = next(i for i, p in enumerate(_DNS_ORDER_RU) if low.startswith(p))
        return (2, i, low)
    return (1, 0, low)


# ── DNS wire-format helpers ───────────────────────────────────────────────────

def _build_dns_query(domain: str) -> bytes:
    """Собирает DNS-запрос в wire-формате (RFC 1035)."""
    tx_id = os.urandom(2)
    flags = b'\x01\x00'       # RD=1
    qdcount = b'\x00\x01'
    ancount = nscount = arcount = b'\x00\x00'
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'

    qtype  = b'\x00\x01'   # A
    qclass = b'\x00\x01'   # IN
    question = qname + qtype + qclass

    return header + question


def _parse_dns_response(data: bytes, expected_tx_id: bytes) -> Union[List[str], str]:
    """
    Парсит DNS-ответ wire-формата.
    Возвращает список IPv4-адресов, "NXDOMAIN", или "PARSE_ERR".
    """
    if len(data) < 12:
        return "PARSE_ERR"
    if data[:2] != expected_tx_id:
        return "PARSE_ERR"

    flags   = struct.unpack(">H", data[2:4])[0]
    rcode   = flags & 0x0F
    ancount = struct.unpack(">H", data[6:8])[0]

    if rcode == 3:
        return "NXDOMAIN"
    if rcode != 0 or ancount == 0:
        return "PARSE_ERR"

    # Пропускаем заголовок (12) + вопрос
    offset = 12
    try:
        while True:
            if offset >= len(data):
                return "PARSE_ERR"
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:   # pointer
                offset += 2
                break
            offset += length + 1
        offset += 4  # qtype + qclass
    except IndexError:
        return "PARSE_ERR"

    ips = []
    for _ in range(ancount):
        try:
            if offset >= len(data):
                break
            # Имя (может быть pointer)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            if offset + 10 > len(data):
                break
            rtype  = struct.unpack(">H", data[offset:offset+2])[0]
            rdlen  = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10

            if rtype == 1 and rdlen == 4:   # A record
                ip = ".".join(str(b) for b in data[offset:offset+4])
                ips.append(ip)
            offset += rdlen
        except (IndexError, struct.error):
            break

    return ips if ips else "PARSE_ERR"


# ── UDP low-level ────────────────────────────────────────────────────────────

async def _resolve_udp_native(nameserver: str, domain: str, timeout: float) -> Union[List[str], str]:
    """
    UDP DNS-запрос напрямую через asyncio DatagramProtocol.
    Возвращает список IP или "NXDOMAIN"/"PARSE_ERR" при ошибке.
    """
    query = _build_dns_query(domain)
    tx_id = query[:2]

    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)
        def error_received(self, exc):
            if not future.done():
                future.set_exception(exc)
        def connection_lost(self, exc):
            if not future.done():
                future.set_exception(exc or ConnectionError("UDP closed"))

    transport, _ = await loop.create_datagram_endpoint(
        _Proto, remote_addr=(nameserver, 53)
    )
    try:
        transport.sendto(query)
        resp_data = await asyncio.wait_for(future, timeout=timeout)
        return _parse_dns_response(resp_data, tx_id)
    finally:
        transport.close()


def _doh_exc_status(exc: Exception) -> str:
    """
    Классификация исключения DoH-пробы.
    BLOCKED — активное вмешательство: подмена/ошибка сертификата (MITM)
    или сброс соединения при подключении (SNI-блокировка).
    ERROR  — прочие ошибки (HTTP 5xx, кривой ответ, протокол).
    """
    e = exc
    while e is not None:
        if isinstance(e, ssl.SSLError):
            return "BLOCKED"
        e = getattr(e, "__cause__", None) or getattr(e, "__context__", None)
    if isinstance(exc, httpx.ConnectError):
        return "BLOCKED"
    return "ERROR"

# ── Batch probes ──────────────────────────────────────────────────────────────

async def _probe_udp_all(nameserver: str, domains: list) -> dict:
    async def _query(domain):
        try:
            res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
            if isinstance(res, list):
                return domain, "OK", res
            if res == "NXDOMAIN":
                return domain, "NXDOMAIN", None
            return domain, "ERROR", None
        except asyncio.TimeoutError:
            return domain, "TIMEOUT", None
        except Exception:
            return domain, "ERROR", None

    completed = await asyncio.gather(*[_query(d) for d in domains])

    ok = timeout_cnt = error = 0
    results = {}
    for domain, status, res in completed:
        if status == "OK":
            results[domain] = res
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            error += 1

    return {"ok": ok, "timeout": timeout_cnt, "error": error, "results": results}

# ── Публичные функции ─────────────────────────────────────────────────────────

async def collect_stub_ips_silently() -> set:
    """Тихо собирает IP заглушек провайдера (если DNS-тест не запущен)."""
    probe = None
    for udp_ip, _ in config.DNS_UDP_SERVERS:
        probe = await _probe_udp_all(udp_ip, config.DNS_CHECK_DOMAINS)
        if probe["ok"] > 0:
            break

    if not probe or not probe.get("results"):
        return set()

    ip_count: dict = {}
    for res in probe["results"].values():
        if isinstance(res, list):
            for ip in res:
                ip_count[ip] = ip_count.get(ip, 0) + 1
    return {ip for ip, count in ip_count.items() if count >= 2}


# ── Тест 1: Проверка доступности DNS-серверов ────────────────────────────────

class _SingleQueryProto(asyncio.DatagramProtocol):
    """Одиночный UDP DNS-запрос: отдаёт (data, t_recv) в future."""

    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, _addr):
        t_recv = time.perf_counter()
        if not self.fut.done():
            self.fut.set_result((data, t_recv))

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        err = exc or ConnectionError("Socket closed")
        if not self.fut.done():
            self.fut.set_exception(err)

async def probe_resolver_ip(server_ip: str, timeout: float = 2.0) -> Optional[str]:
    """IP вышестоящего резолвера через server_ip:53.

    A whoami.akamai.net: авторитетный сервер возвращает адрес рекурсивного
    резолвера, от которого пришёл запрос. Если роутер работает DNS-релеем
    (dnsmasq/unbound), это IP его upstream. None — не удалось."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    transport = None
    try:
        q = _build_dns_query("whoami.akamai.net")
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SingleQueryProto(fut), remote_addr=(server_ip, 53)
        )
        transport.sendto(q)
        data, _t = await asyncio.wait_for(fut, timeout=timeout)
        parsed = _parse_dns_response(data, q[:2])
        if isinstance(parsed, list) and parsed:
            return parsed[0]
    except Exception:
        pass
    finally:
        if transport:
            transport.close()
    return None


# ── SOCKS5 UDP-relay (весь трафик теста 1 идёт через прокси) ─────────────────

_SOCKS5_RE = re.compile(
    r"^socks5h?://(?:(?P<user>[^:/@\s]+)(?::(?P<pass>[^@/\s]*))?@)?"
    r"(?P<host>[^:/@\s]+):(?P<port>\d+)/?$"
)


def _parse_socks_proxy(proxy_url: Optional[str]) -> Optional[Tuple[str, int, Optional[str], Optional[str]]]:
    """Разбирает socks5://[user:pass@]host:port → (host, port, user, password)."""
    if not proxy_url:
        return None
    m = _SOCKS5_RE.match(proxy_url.strip())
    if not m:
        return None
    return (m.group("host"), int(m.group("port")),
            m.group("user") or None, m.group("pass") or None)


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
            head = b"\x00\x00\x00\x01" + socket.inet_aton(addr) + struct.pack("!H", port)
            transport.sendto(head + q)
            data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
            payload = _unwrap_socks_udp(data)
            if payload is None:
                return None, None
            elapsed_ms = round((t_recv - t0) * 1000, 1)
            return elapsed_ms, _parse_dns_response(payload, tx_id)
        except Exception:
            return None, None
        finally:
            if transport:
                transport.close()
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


async def check_dns_availability() -> dict:
    """
    Тест 1: доступность DNS-серверов + пинг + детект подмены.

    Двух-фазная схема (чтобы пинги и детект подмены не конфликтовали):
      Фаза A (UDP): доверенные домены (вне цензуры) — по ним меряем пинг
                    и считаем, что сервер вообще жив.
      Фаза B (UDP): если сервер жив — те же серверы опрашиваются по
                    запрещённым доменам; сравнение UDP-ответа с DoH-правдой
                    выявляет подмену. "Молчание" на запрещённом домене тоже
                    считается подменой (блок без ответа), а не недоступностью.

    DoH (Wire) сразу проверяет запрещённые домены — это эталон "правды",
    с которым сравниваются UDP-ответы. Один TLS-коннект на сервер, запросы
    последовательно (фикс плоских 300мс ТСПУ).

    Таблица: Провайдер | DoH мин | UDP мин | Реальный UDP резолвер | Подмена
    """
    servers = getattr(config, "DNS_AVAILABILITY_SERVERS", [])
    # Доверенные домены (не под цензурой) — по ним пинг и доступность
    allowed = getattr(config, "DNS_AVAILABILITY_DOMAINS", ["vk.ru", "gosuslugi.ru"])
    # Запрещённые домены (из теста 1) — по ним выявляем подмену
    forbidden = getattr(config, "DNS_CHECK_DOMAINS", [])
    timeout = getattr(config, "DNS_AVAILABILITY_TIMEOUT", config.DNS_CHECK_TIMEOUT)

    if not servers:
        console.print("[yellow]DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.[/yellow]")
        return {"doh_ok": 0, "doh_total": 0, "dot_ok": 0, "dot_total": 0,
                "udp_ok": 0, "udp_total": 0,
                "hijacked_brands": [], "resolvers_total": 0}

    proxy_url = getattr(config, "PROXY_URL", None)
    socks_proxy = _parse_socks_proxy(proxy_url) if proxy_url else None

    # ── Группируем серверы ────────────────────────────────────────────────────
    # Запись: [адрес, имя, тип, порт?] — 4-й элемент опционален
    # (по умолчанию: UDP 53, DoH 443, DoT 853) — для нестандартных портов.
    def _entry_port(s: list, default: int) -> int:
        try:
            return int(s[3]) if len(s) > 3 else default
        except (TypeError, ValueError):
            return default

    udp_servers  = [(s[0], s[1], _entry_port(s, 53)) for s in servers if s[2] == "udp"]
    wire_servers = [(s[0], s[1], _entry_port(s, 443)) for s in servers if s[2] == "doh_wire"]
    doh_servers  = wire_servers  # только Wire
    dot_servers  = [(s[0], s[1], _entry_port(s, 853)) for s in servers if s[2] == "dot"]

    def _doh_url_with_port(url: str, port: int) -> str:
        """Вставляет/заменяет порт в https:// URL DoH (нестандартный порт)."""
        m = re.match(r"^(https?://)([^/]+)(/.*)?$", url)
        if not m:
            return url
        scheme, host, path = m.group(1), m.group(2), m.group(3) or ""
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        return f"{scheme}{host}:{port}{path}"

    # ── Уникальные имена провайдеров в порядке появления ─────────────────────
    all_names: list[str] = []
    seen: set[str] = set()
    for _, n, _ in (doh_servers + udp_servers + dot_servers):
        if n not in seen:
            all_names.append(n)
            seen.add(n)
    # Ручной порядок: популярные (google/cf/quad9/adguard) → остальные по
    # алфавиту → российские в конце (xbox/comss/yandex/geohide/msk-ix/нсди)
    all_names.sort(key=_dns_name_sort_key)

    doh_by_name: dict[str, list[str]] = {}
    udp_by_name: dict[str, list[str]] = {}
    dot_by_name: dict[str, list[str]] = {}
    doh_ports: dict[str, list[int]] = {}
    udp_ports: dict[str, list[int]] = {}
    dot_ports: dict[str, list[int]] = {}
    for a, n, p in doh_servers:
        doh_by_name.setdefault(n, []).append(a)
        doh_ports.setdefault(n, []).append(p)
    for a, n, p in udp_servers:
        udp_by_name.setdefault(n, []).append(a)
        udp_ports.setdefault(n, []).append(p)
    for a, n, p in dot_servers:
        dot_by_name.setdefault(n, []).append(a)
        dot_ports.setdefault(n, []).append(p)

    # ── Заголовок ─────────────────────────────────────────────────────────────
    console.print(
        f"\n[bold]Проверка доступности DNS-серверов[/bold]  "
        f"[dim]DoH: {len(doh_servers)} | DoT: {len(dot_servers)} | UDP: {len(udp_servers)}"
        f" | Запрещённых: {len(forbidden)} | Доверенных: {len(allowed)}"
        f" | timeout: {timeout}s[/dim]"
    )
    console.print()

    # ── Таблица эндпоинтов ────────────────────────────────────────────────────
    from rich.table import Table as _Table
    ep_table = _Table(show_header=True, header_style="bold magenta",
                      border_style="dim", box=None, pad_edge=False)
    ep_table.add_column("Провайдер", style="bold cyan", no_wrap=True, min_width=16)
    ep_table.add_column("DoH эндпоинты", style="dim", no_wrap=False)
    if dot_servers:
        ep_table.add_column("DoT", style="dim", no_wrap=True)
    ep_table.add_column("UDP",            style="dim",   no_wrap=True)

    for name in all_names:
        doh_urls = doh_by_name.get(name, [])
        udp_ips  = udp_by_name.get(name, [])
        dot_eps  = dot_by_name.get(name, [])
        dports, uports, eports = (doh_ports.get(name, []), udp_ports.get(name, []),
                                  dot_ports.get(name, []))
        # Порт показываем, если нестандартный
        doh_disp = [_doh_url_with_port(u, p) if p != 443 else u
                    for u, p in zip(doh_urls, dports)]
        udp_disp = [f"{ip}:{p}" if p != 53 else ip for ip, p in zip(udp_ips, uports)]
        dot_disp = [f"{e}:{p}" if p != 853 else e for e, p in zip(dot_eps, eports)]
        # Номера эндпоинтов (#1..#N) — чтобы сопоставить с «Имя #N» в таблице результатов
        doh_str  = "\n".join(f"{u} [dim]#{i+1}[/dim]" for i, u in enumerate(doh_disp)) if doh_disp else "[dim]—[/dim]"
        udp_str  = ", ".join(f"{ip} [dim]#{i+1}[/dim]" for i, ip in enumerate(udp_disp)) if udp_disp else "[dim]—[/dim]"
        dot_str  = ", ".join(f"{e} [dim]#{i+1}[/dim]" for i, e in enumerate(dot_disp)) if dot_disp else "[dim]—[/dim]"
        ep_row = [name, doh_str]
        if dot_servers:
            ep_row.append(dot_str)
        ep_row.append(udp_str)
        ep_table.add_row(*ep_row)

    console.print(ep_table)
    console.print()

    # ── Домены проверки и дисклеймер ──────────────────────────────────────────
    console.print(
        f"[bold]Заблокированные домены для проверки:[/bold] {', '.join(forbidden)}\n"
        f"[bold]Незаблокированные домены для проверки:[/bold] {', '.join(allowed)}\n"
        "[bold yellow]ВНИМАНИЕ:[/bold yellow] Это независимая проверка и она не использует ваши настроенные DNS!"
    )
    if proxy_url and not socks_proxy:
        console.print(
            "[yellow]Прокси не SOCKS5 — UDP-пробы идут напрямую: "
            "через HTTP-прокси UDP-релей невозможен.[/yellow]"
        )

    # ── Счётчик прогресса ─────────────────────────────────────────────────────
    total_probes  = len(doh_servers) + len(udp_servers) + len(dot_servers)
    done_count    = 0
    progress_lock = asyncio.Lock()

    def _redraw_progress():
        import sys
        bar = f"  Проверка серверов... {done_count}/{total_probes}"
        sys.stderr.write(f"\r{bar}   ")
        sys.stderr.flush()

    async def _tick():
        nonlocal done_count
        async with progress_lock:
            done_count += 1
            _redraw_progress()

    # ── данные замеров ────────────────────────────────────────────────────────
    # raw[(kind, addr, name)][domain] = elapsed_ms or None (тайминг/успешность)
    raw: dict[tuple, dict[str, Optional[int]]] = {}
    fail_reasons: dict[tuple, str] = {}   # (kind, addr, name) -> ярлык причины фейла
    # Ответы по доменам: (kind, addr, name, domain) -> list[ip] | "NXDOMAIN" |
    # "PARSE_ERR" | None (таймаут/нет ответа). Нужны для сравнения подмены.
    udp_answers: dict[tuple, object] = {}
    doh_answers: dict[tuple, object] = {}
    dot_answers: dict[tuple, object] = {}

    # ── UDP probe: фаза A (доверенные) → фаза B (запрещённые, если жив) ──────
    async def _probe_udp(addr: str, name: str, port: int = 53) -> None:
        key = ("udp", addr, name)
        loop = asyncio.get_running_loop()
        udp_sem = asyncio.Semaphore(getattr(config, "DNS_UDP_CONCURRENCY", 15))

        async def _wait(domain: str):
            async with udp_sem:
                if socks_proxy:
                    elapsed_ms, parsed = await _Socks5UdpRelay(*socks_proxy).query(
                        addr, domain, timeout, port
                    )
                    ok = isinstance(parsed, list)   # "успех" — только с реальными IP
                    return domain, (elapsed_ms if ok else None), parsed
                q = _build_dns_query(domain)
                tx_id = q[:2]
                fut = loop.create_future()
                transport = None
                t0 = time.perf_counter()
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _SingleQueryProto(fut), remote_addr=(addr, port)
                    )
                    transport.sendto(q)
                    data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
                    elapsed_ms = round((t_recv - t0) * 1000, 1)
                    parsed = _parse_dns_response(data, tx_id)
                    ok = isinstance(parsed, list)   # "успех" — только с реальными IP
                    return domain, (elapsed_ms if ok else None), parsed
                except Exception:
                    return domain, None, None
                finally:
                    if transport:
                        transport.close()

        # Фаза A: доступность по доверенным доменам
        pairs_a = await asyncio.gather(*[_wait(d) for d in allowed])
        available = any(e is not None for _, e, _ in pairs_a)
        res = dict((d, e) for d, e, _ in pairs_a)
        for d, _e, parsed in pairs_a:
            udp_answers[("udp", addr, name, d)] = parsed
        # Фаза B: только живому серверу — запрещённые домены на проверку подмены
        if available and forbidden:
            pairs_b = await asyncio.gather(*[_wait(d) for d in forbidden])
            res.update((d, e) for d, e, _ in pairs_b)
            for d, _e, parsed in pairs_b:
                udp_answers[("udp", addr, name, d)] = parsed
        raw[key] = res
        await _tick()

    # ── DoH JSON probe (не вызывается, оставлен для совместимости) ───────────
    async def _probe_doh_json(addr: str, name: str) -> None:
        key = ("doh_json", addr, name)
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(getattr(config, "DNS_DOH_CONCURRENCY", 20))

        async def _one(domain: str, client: httpx.AsyncClient):
            async with doh_sem:
                t0 = time.perf_counter()
                try:
                    resp = await client.get(addr, params={"name": domain, "type": "A"})
                    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                    if resp.status_code != 200:
                        return domain, None, None
                    data = resp.json()
                    if data.get("Status") == 3:
                        return domain, None, "NXDOMAIN"
                    ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                    return domain, (elapsed_ms if ips else None), (ips if ips else None)
                except Exception:
                    return domain, None, None

        try:
            async with httpx.AsyncClient(
                timeout=cli_timeout,
                headers={"Accept": "application/dns-json", "User-Agent": config.USER_AGENT},
                proxy=proxy_url, trust_env=False,
            ) as client:
                try:
                    warmup_q = forbidden[0] if forbidden else "google.com"
                    await client.get(addr, params={"name": warmup_q, "type": "A"})
                except Exception:
                    pass
                pairs = await asyncio.gather(*[_one(d, client) for d in forbidden])
        except Exception:
            pairs = [(d, None, None) for d in forbidden]
        raw[key] = dict((d, e) for d, e, _ in pairs)
        for d, _e, parsed in pairs:
            doh_answers[("doh_json", addr, name, d)] = parsed
        await _tick()

    # ── DoH Wire probe: эталон "правды" по запрещённым доменам ───────────────
    # Один клиент на сервер, один TLS-коннект, боевые запросы последовательно
    # (иначе каждый открывает своё соединение и платит +300мс ТСПУ).
    async def _probe_doh_wire(addr: str, name: str, port: int = 443) -> None:
        key = ("doh_wire", addr, name)
        orig_addr = addr   # адрес до пининга — по нему храню ответы (совпадает с doh_by_name)
        # Нестандартный порт — вставляем в URL до пининга
        if port != 443:
            addr = _doh_url_with_port(addr, port)
        # Привязка к IP выбранного семейства: коннект по A-/AAAA-записи,
        # SNI и Host — от имени сервера
        addr, ehost = await pin_host(addr)
        ehost_headers = {"Host": ehost} if ehost else {}
        ehost_ext = {"sni_hostname": ehost} if ehost else None
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(getattr(config, "DNS_DOH_CONCURRENCY", 20))
        single_conn = httpx.Limits(max_connections=1, max_keepalive_connections=1)

        async def _do_probe() -> list:
            conn_state = {"stage": "init"}

            async def _one(domain: str, client: httpx.AsyncClient):
                async with doh_sem:
                    query = _build_dns_query(domain)
                    tx_id = query[:2]
                    last_err: Optional[Exception] = None
                    for attempt in range(2):
                        if attempt:
                            await asyncio.sleep(0.3 + os.urandom(1)[0] / 255 * 0.7)
                        try:
                            t0 = time.perf_counter()
                            resp = await client.post(
                                addr, content=query,
                                headers={
                                    "Content-Type": "application/dns-message",
                                    "Accept":       "application/dns-message",
                                    "User-Agent":   config.USER_AGENT,
                                    **ehost_headers,
                                },
                                extensions=ehost_ext,
                            )
                            if resp.status_code != 200:
                                dns_b64 = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
                                t0 = time.perf_counter()
                                resp = await client.get(
                                    addr, params={"dns": dns_b64},
                                    headers={"Accept": "application/dns-message",
                                             "User-Agent": config.USER_AGENT,
                                             **ehost_headers},
                                    extensions=ehost_ext,
                                )
                            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                            if resp.status_code != 200:
                                return domain, None, None
                            result = _parse_dns_response(resp.content, tx_id)
                            ok = isinstance(result, list)
                            return domain, (elapsed_ms if ok else None), result
                        except Exception as err:
                            last_err = err
                    if last_err is not None:
                        _record_fail(last_err)
                    return domain, None, None

            try:
                async with httpx.AsyncClient(
                    timeout=cli_timeout,
                    proxy=proxy_url, trust_env=False, http2=True,
                    limits=single_conn,
                ) as client:
                    async def _trace_hook(event_name: str, info):
                        if event_name == "connection.connect_tcp.started":
                            conn_state["stage"] = "tcp_connect"
                        elif event_name == "connection.connect_tcp.complete":
                            conn_state["stage"] = "tcp_connected"
                        elif event_name == "connection.start_tls.started":
                            conn_state["stage"] = "tls_handshake"
                        elif event_name == "connection.start_tls.complete":
                            conn_state["stage"] = "tls_connected"

                    def _record_fail(err: Exception) -> None:
                        if key in fail_reasons:
                            return
                        stage = conn_state.get("stage", "init")
                        if isinstance(err, (httpx.ReadTimeout, httpx.ReadError,
                                            httpx.RemoteProtocolError, httpx.WriteTimeout,
                                            httpx.PoolTimeout)):
                            label, _, _ = classify_read_error(err, 0, stage=stage)
                        else:
                            label, _, _ = classify_connect_error(err, 0, stage=stage)
                        fail_reasons[key] = label

                    try:
                        warmup = _build_dns_query(forbidden[0] if forbidden else "google.com")
                        await client.post(
                            addr, content=warmup,
                            headers={"Content-Type": "application/dns-message",
                                     "Accept": "application/dns-message",
                                     "User-Agent": config.USER_AGENT,
                                     **ehost_headers},
                            extensions={**ehost_ext, "trace": _trace_hook} if ehost_ext else {"trace": _trace_hook},
                        )
                    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException) as err:
                        _record_fail(err)
                        return [(d, None, None) for d in forbidden]
                    except Exception:
                        pass  # Сервер жив, но вернул 400/500 — продолжаем

                    # Боевые запросы ПОСЛЕДОВАТЕЛЬНО (фикс плоских 300мс ТСПУ)
                    results = []
                    for d in forbidden:
                        results.append(await _one(d, client))
                    return results
            except Exception as err:
                if isinstance(err, (TimeoutError, asyncio.TimeoutError)):
                    fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
                else:
                    fail_reasons.setdefault(
                        key, f"[red]UNKNOWN[/red] [dim]{type(err).__name__}[/dim]"
                    )
                return [(d, None, None) for d in forbidden]

        try:
            pairs = await asyncio.wait_for(_do_probe(), timeout=timeout * 2 + 3.0)
            raw[key] = dict((d, e) for d, e, _ in pairs)
            for d, _e, parsed in pairs:
                doh_answers[("doh_wire", orig_addr, name, d)] = parsed
        except (asyncio.TimeoutError, Exception):
            fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
            raw[key] = {d: None for d in forbidden}
            for d in forbidden:
                doh_answers[("doh_wire", orig_addr, name, d)] = None
        finally:
            await _tick()

    # ── DoT probe (RFC 7858): TLS:853, wire-запросы с 2-байт length-prefix ───
    # Один TLS-коннект на сервер, запросы последовательно (как DoH Wire).
    # httpx DoT не умеет — сырой asyncio. Прокси не поддерживается (как UDP).
    def _split_dot_endpoint(addr: str) -> tuple:
        """'host[:port]' → (host, port); порт по умолчанию 853."""
        if ":" in addr:
            host, _, port = addr.rpartition(":")
            return host, int(port)
        return addr, 853

    async def _probe_dot(addr: str, name: str, port: int = 853) -> None:
        key = ("dot", addr, name)
        host, ep_port = _split_dot_endpoint(addr)
        # 4-й элемент конфига переопределяет порт; иначе — порт из адреса ('host:port')
        if port == 853:
            port = ep_port
        # Коннект по IP выбранного семейства (config.IP_VERSION),
        # SNI/сертификат — по имени сервера (для IP-литерала — IP-SAN)
        if is_ip_literal(host):
            connect_host = server_hostname = host
        else:
            ip = await get_resolved_ip(host)
            connect_host, server_hostname = (ip or host), host
        ctx = ssl.create_default_context()
        conn_state = {"stage": "init"}

        def _record_fail(err: Exception) -> None:
            if key in fail_reasons:
                return
            stage = conn_state.get("stage", "init")
            label, _, _ = classify_connect_error(err, 0, stage=stage)
            fail_reasons[key] = label

        async def _one(domain: str, reader, writer) -> tuple:
            q = _build_dns_query(domain)
            tx_id = q[:2]
            try:
                t0 = time.perf_counter()
                writer.write(struct.pack("!H", len(q)) + q)
                await writer.drain()
                (n,) = struct.unpack("!H", await asyncio.wait_for(
                    reader.readexactly(2), timeout=timeout))
                data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                parsed = _parse_dns_response(data, tx_id)
                ok = isinstance(parsed, list)
                return domain, (elapsed_ms if ok else None), parsed
            except Exception:
                return domain, None, None

        async def _do_probe() -> list:
            try:
                conn_state["stage"] = "tcp_connect"
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, port, ssl=ctx,
                                            server_hostname=server_hostname),
                    timeout=timeout,
                )
                conn_state["stage"] = "tls_connected"
            except Exception as err:
                if isinstance(err, ssl.SSLError):
                    conn_state["stage"] = "tls_handshake"
                _record_fail(err)
                return [(d, None, None) for d in forbidden]
            try:
                # warmup: убедиться, что сервер реально отвечает по TLS
                q = _build_dns_query(forbidden[0] if forbidden else "google.com")
                writer.write(struct.pack("!H", len(q)) + q)
                await writer.drain()
                (n,) = struct.unpack("!H", await asyncio.wait_for(
                    reader.readexactly(2), timeout=timeout))
                await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                # Боевые запросы ПОСЛЕДОВАТЕЛЬНО (один поток, как DoH Wire)
                results = []
                for d in forbidden:
                    results.append(await _one(d, reader, writer))
                return results
            except Exception as err:
                _record_fail(err)
                return [(d, None, None) for d in forbidden]
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        try:
            pairs = await asyncio.wait_for(_do_probe(), timeout=timeout * 2 + 3.0)
            raw[key] = dict((d, e) for d, e, _ in pairs)
            for d, _e, parsed in pairs:
                dot_answers[("dot", addr, name, d)] = parsed
        except (asyncio.TimeoutError, Exception):
            fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
            raw[key] = {d: None for d in forbidden}
            for d in forbidden:
                dot_answers[("dot", addr, name, d)] = None
        finally:
            await _tick()

    # ── Запускаем: Wire + DoT + UDP ──────────────────────────────────────────
    probe_gate = asyncio.Semaphore(getattr(config, "DNS_PROBE_CONCURRENCY", 3))

    # ── Выходной резолвер: A whoami.akamai.net ────────────────────────────────
    egress: dict[tuple, Optional[str]] = {}

    async def _probe_egress(addr: str, name: str, port: int = 53) -> None:
        key = ("egress", addr, name)
        if socks_proxy:
            _elapsed, parsed = await _Socks5UdpRelay(*socks_proxy).query(
                addr, "whoami.akamai.net", timeout, port
            )
            egress[key] = parsed[0] if isinstance(parsed, list) and parsed else None
            return
        loop = asyncio.get_running_loop()
        result = None
        # Повторный запрос при пустом ответе: одиночная проба whoami
        # теряется (таймаут/пустой ответ) — один ретрай убирает «выход н/д»
        for attempt in range(2):
            fut: asyncio.Future = loop.create_future()
            transport = None
            try:
                q = _build_dns_query("whoami.akamai.net")
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _SingleQueryProto(fut), remote_addr=(addr, port)
                )
                transport.sendto(q)
                data, _t = await asyncio.wait_for(fut, timeout=timeout)
                parsed = _parse_dns_response(data, q[:2])
                result = parsed[0] if isinstance(parsed, list) and parsed else None
            except Exception:
                result = None
            finally:
                if transport:
                    transport.close()
            if result:
                break
            if attempt == 0:
                await asyncio.sleep(0.2)   # не попасть в тот же слот таймаута
        egress[key] = result

    async def _probe_udp_gated(addr, name, port):
        async with probe_gate:
            await _probe_udp(addr, name, port)

    async def _probe_doh_wire_gated(addr, name, port):
        async with probe_gate:
            await _probe_doh_wire(addr, name, port)
    async def _probe_dot_gated(addr, name, port):
        async with probe_gate:
            await _probe_dot(addr, name, port)

    egress_sem = asyncio.Semaphore(getattr(config, "DNS_EGRESS_CONCURRENCY", 10))

    async def _probe_egress_gated(addr, name, port):
        async with egress_sem:
            await _probe_egress(addr, name, port)

    # ── Имена организаций выходных IP (Team Cymru через DoH) ──────────────────
    _CYMRU_DOH = tuple(getattr(config, "CYMRU_DOH_SERVERS",
                               ("https://dns.google/resolve",
                                "https://cloudflare-dns.com/dns-query")))

    def _doh_txt_fields(txt: str) -> list:
        return [p.strip() for p in txt.strip('"').split("|")]

    async def _lookup_asn_name(client: httpx.AsyncClient, ip: str) -> Optional[str]:
        if ip.count(".") != 3:
            return None
        rev = ".".join(reversed(ip.split(".")))
        asn = None
        for url, ehost in [await pin_host(u) for u in _CYMRU_DOH]:
            try:
                resp = await client.get(
                    url, params={"name": f"{rev}.origin.asn.cymru.com", "type": "TXT"},
                    headers={"Host": ehost} if ehost else None,
                    extensions={"sni_hostname": ehost} if ehost else None,
                )
                answers = resp.json().get("Answer", []) if resp.status_code == 200 else []
                if answers:
                    m = re.match(r"\s*(\d+)", _doh_txt_fields(answers[0]["data"])[0])
                    if m:
                        asn = m.group(1)
                        break
            except Exception:
                continue
        if not asn:
            return None
        for url, ehost in [await pin_host(u) for u in _CYMRU_DOH]:
            try:
                resp = await client.get(
                    url, params={"name": f"AS{asn}.asn.cymru.com", "type": "TXT"},
                    headers={"Host": ehost} if ehost else None,
                    extensions={"sni_hostname": ehost} if ehost else None,
                )
                answers = resp.json().get("Answer", []) if resp.status_code == 200 else []
                if answers:
                    fields = _doh_txt_fields(answers[0]["data"])
                    name = fields[-1] if len(fields) >= 3 else fields[0]
                    return re.sub(r"\s+", " ", name).strip() or None
            except Exception:
                continue
        return None

    _ASN_CACHE_FILE = getattr(
        config, "ASN_CACHE_FILE",
        os.path.join(tempfile.gettempdir(), "dpi_detector_asn_cache.json"),
    ) or os.path.join(tempfile.gettempdir(), "dpi_detector_asn_cache.json")

    def _load_asn_cache() -> dict:
        try:
            with open(_ASN_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    async def _resolve_asn_names() -> dict[str, str]:
        uniq = sorted({e for e in egress.values()
                      if e and e != "0.0.0.0" and get_fake_ip_type(e) != "fakeip"})
        if not uniq:
            return {}
        cache = _load_asn_cache()
        out = {i: cache[i] for i in uniq if isinstance(cache.get(i), str)}
        missing = [i for i in uniq if i not in out]
        if not missing:
            return out
        headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}
        sem = asyncio.Semaphore(getattr(config, "DNS_ASN_CONCURRENCY", 8))
        fresh: dict[str, str] = {}
        async with httpx.AsyncClient(
            timeout=4, headers=headers,
            proxy=getattr(config, "PROXY_URL", None), trust_env=False,
        ) as cli:
            async def one(uip: str):
                async with sem:
                    nm = await _lookup_asn_name(cli, uip)
                    return uip, nm
            for uip, nm in await asyncio.gather(*[one(i) for i in missing]):
                if nm:
                    out[uip] = nm
                    fresh[uip] = nm
        if fresh:
            cache.update(fresh)
            try:
                with open(_ASN_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(cache, f)
            except Exception:
                pass
        return out

    _redraw_progress()
    if udp_servers:
        await asyncio.gather(
            *[_probe_udp_gated(a, n, p) for a, n, p in udp_servers]
          + [_probe_egress_gated(a, n, p) for a, n, p in udp_servers]
        )

    # Орг-имена egress резолвим в фоне — параллельно с DoH/DoT-пробами,
    # чтобы не ждать их в конце (раньше это давало +секунды после теста)
    org_task = asyncio.create_task(_resolve_asn_names()) if udp_servers else None

    if wire_servers:
        await asyncio.gather(*[_probe_doh_wire_gated(a, n, p) for a, n, p in wire_servers])
    if dot_servers:
        await asyncio.gather(*[_probe_dot_gated(a, n, p) for a, n, p in dot_servers])

    import sys
    sys.stderr.write(f"\r  Проверено серверов: {done_count}/{total_probes}          \n")
    sys.stderr.flush()

    org_names = await org_task if org_task is not None else {}

    def _org_label(eip: str) -> str:
        name = org_names.get(eip)
        if not name:
            return eip
        return name.split(" - ", 1)[0].strip() or name

    # ── Классификация выходных резолверов ─────────────────────────────────────
    def _net24(ip: str) -> str:
        parts = ip.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else ip

    def _brand(nm: str) -> str:
        return nm.split(" (", 1)[0].strip()

    name_ips: dict[str, list[str]] = {}
    net_brands: dict[str, set] = {}
    for (_ekind, _eaddr, ename), eip in egress.items():
        if not eip or eip == "0.0.0.0":
            continue
        if get_fake_ip_type(eip) == "fakeip":
            continue           # FakeIP — не реальный резолвер, не учитывать в hijack
        name_ips.setdefault(ename, []).append(eip)
        net_brands.setdefault(_net24(eip), set()).add(_brand(ename))

    def _is_hijacked(eip: str) -> bool:
        return len(net_brands.get(_net24(eip), ())) >= 2

    _DOMESTIC_BRANDS = {"msk-ix", "нсди"}

    def _is_domestic(name: str) -> bool:
        return _brand(name).lower() in _DOMESTIC_BRANDS

    # ── Ячейки единой таблицы ─────────────────────────────────────────────────
    def _kind_stats(kind: str, name: str):
        if kind == "udp":
            addrs = udp_by_name.get(name, [])
        elif kind == "dot":
            addrs = dot_by_name.get(name, [])
        else:
            addrs = doh_by_name.get(name, [])
        vals_all, ok_q, total_q = [], 0, 0
        for a in addrs:
            dm = raw.get((kind, a, name), {})
            vals = [v for v in dm.values() if v is not None]
            vals_all += vals
            ok_q += len(vals)
            total_q += len(dm)
        return vals_all, ok_q, total_q

    def _allowed_vals(a: str, name: str) -> tuple[list, int]:
        """Тайминги по ДОВЕРЕННЫМ доменам для UDP (реальная задержка резолвера),
        заблокированные домены не участвуют — их 3–5мс заглушки занижают мин."""
        dm = raw.get(("udp", a, name), {})
        vals = [dm[d] for d in allowed if dm.get(d) is not None]
        return vals, len(allowed)

    def _latency_cell(kind: str, name: str) -> str:
        if kind == "udp":
            addrs = udp_by_name.get(name, [])
        elif kind == "dot":
            addrs = dot_by_name.get(name, [])
        else:
            addrs = doh_by_name.get(name, [])
        if not addrs:
            return "[dim]—[/dim]"
        if kind == "udp":
            lines = []
            for a in addrs:
                vals, total_q = _allowed_vals(a, name)
                ok_q = len(vals)
                if not vals:
                    lines.append("[red]TIMEOUT[/red]")
                    continue
                ratio = f" [dim]{ok_q}/{total_q}[/dim]" if ok_q < total_q else ""
                lines.append(f"[green]{round(min(vals), 1)}мс[/green]{ratio}")
            return "\n".join(lines)
        if kind == "dot":
            # По строке на каждый DoT-эндпоинт (а не агрегат «15/20» по всем):
            # видно, какой эндпоинт мёртв, а какой жив
            lines = []
            for a in addrs:
                dm = raw.get(("dot", a, name), {})
                vals = [v for v in dm.values() if v is not None]
                if not vals:
                    reason = fail_reasons.get(("dot", a, name))
                    lines.append(reason if reason else "[red]TIMEOUT[/red]")
                    continue
                total_q = len(dm)
                ok_q = len(vals)
                ratio = f" [dim]{ok_q}/{total_q}[/dim]" if ok_q < total_q else ""
                lines.append(f"[green]{round(min(vals), 1)}мс[/green]{ratio}")
            return "\n".join(lines)
        vals_all, ok_q, total_q = _kind_stats(kind, name)
        if not vals_all:
            for a in addrs:
                reason = fail_reasons.get((kind, a, name))
                if reason:
                    return reason
            return "[red]TIMEOUT[/red]"
        ratio = f" [dim]{ok_q}/{total_q}[/dim]" if ok_q < total_q else ""
        return f"[green]{round(min(vals_all), 1)}мс[/green]{ratio}"

    def _egress_cell(pname: str) -> str:
        addrs = udp_by_name.get(pname, [])
        if not addrs:
            return "[dim]—[/dim]"
        lines = []
        for a in addrs:
            vals, _ = _allowed_vals(a, pname)
            eip = egress.get(("egress", a, pname))
            if not vals:
                lines.append(f"[dim]{a}: таймаут[/dim]")
            elif not eip or eip == "0.0.0.0":
                lines.append(f"[dim]{a}: выход н/д[/dim]")
            elif get_fake_ip_type(eip) == "fakeip":
                lines.append(f"[magenta]{a}→FakeIP[/magenta]")
            elif _is_domestic(pname):
                lines.append(f"{a}→{_org_label(eip)}")
            elif _known_resolver(_org_label(eip)):
                lines.append(f"[green]{a}→{_org_label(eip)}[/green]")
            else:
                lines.append(f"[red]{a}→{_org_label(eip)}[/red]")
        return "\n".join(lines)

    # ── Глобальная правда по запрещённым доменам (из любого чистого DoH) ───────
    # Все UDP-ответы сравниваются с ЭТИМ единым набором IP, а не с DoH конкретного
    # провайдера. Так проверяются и серверы без своего DoH (MSK-IX, НСДИ, dnsforge...).
    TRUTH_DOH = list(getattr(
        config, "DNS_TRUTH_DOH_SERVERS",
        ["https://cloudflare-dns.com/dns-query",
         "https://dns.google/resolve",
         "https://dns.quad9.net/dns-query"],
    ))

    async def _fetch_truth() -> dict[str, set]:
        truth: dict[str, set] = {}
        if not forbidden:
            return truth
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)

        async def _resolve(endpoint: str) -> dict[str, set]:
            out: dict[str, set] = {}
            try:
                url, ehost = await pin_host(endpoint)
            except Exception:
                url, ehost = endpoint, ""
            headers = {"Content-Type": "application/dns-message",
                       "Accept": "application/dns-message",
                       "User-Agent": config.USER_AGENT}
            if ehost:
                headers["Host"] = ehost
            ext = {"sni_hostname": ehost} if ehost else None
            for d in forbidden:
                try:
                    q = _build_dns_query(d)
                    r = await cli.post(url, content=q, headers=headers, extensions=ext)
                    if r.status_code != 200:
                        continue
                    ips = _parse_dns_response(r.content, q[:2])
                    if isinstance(ips, list):
                        out[d] = set(ips)
                except Exception:
                    continue
            return out

        try:
            async with httpx.AsyncClient(timeout=cli_timeout, proxy=proxy_url,
                                         trust_env=False, http2=True) as cli:
                results = await asyncio.gather(*[_resolve(e) for e in TRUTH_DOH])
        except Exception:
            return truth
        for r in results:
            for d, ips in r.items():
                truth.setdefault(d, set()).update(ips)
        return truth

    truth_ips = await _fetch_truth()

    # Fallback для колонки "Подмена": если глобальная правда из чистых DoH
    # (DNS_TRUTH_DOH_SERVERS) не собралась, строим её из ответов любого живого
    # DoH-wire-резолвера из таблицы. Иначе судить не с чем и колонка пустая.
    if not truth_ips:
        for (kind, _addr, _name, d), parsed in doh_answers.items():
            if kind != "doh_wire":
                continue
            if isinstance(parsed, list) and parsed:
                real = [ip for ip in parsed if get_fake_ip_type(ip) != "fakeip"]
                if real:
                    truth_ips.setdefault(d, set()).update(real)

    def _udp_server_available(a: str, name: str) -> bool:
        dm = raw.get(("udp", a, name), {})
        return any(dm.get(d) is not None for d in allowed)

    def _udp_ips(a: str, name: str, domain: str) -> set:
        p = udp_answers.get(("udp", a, name, domain))
        return set(p) if isinstance(p, list) else set()

    def _fakeip_sub(a: str, name: str) -> int:
        """Сколько запрещённых доменов вернули FakeIP (198.18.0.0/15) — прозрачный прокси."""
        n = 0
        for d in forbidden:
            ips = _udp_ips(a, name, d)
            if ips and any(get_fake_ip_type(ip) == "fakeip" for ip in ips):
                n += 1
        return n

    def _subst_line(a: str, name: str) -> str:
        """Оценка подмены для ОДНОГО UDP-адреса (8.8.4.4 / 8.8.8.8 отдельно).
        Сравнивает его ответы с ГЛОБАЛЬНОЙ DoH-правдой по запрещённым доменам."""
        judged, sub = _subst_counts(a, name)
        if judged == 0:
            return "[dim]—[/dim]"
        frac = f"{sub}/{len(forbidden)}"
        if _fakeip_sub(a, name) > 0:
            # FakeIP — прозрачный прокси (sing-box/mihomo/clash), а не подмена провайдером
            return f"[magenta]{frac}[/magenta]"
        # красный — всё подменяется (5/5); жёлтый — частично (1..4/5); зелёный — 0/5
        if sub == len(forbidden):
            return f"[red]{frac}[/red]"
        if sub == 0:
            return f"[green]{frac}[/green]"
        return f"[yellow]{frac}[/yellow]"

    def _subst_counts(a: str, name: str) -> tuple[int, int]:
        """(judged, sub) для одного UDP-адреса; judged==0 → судить нельзя (—)."""
        if not _udp_server_available(a, name):
            return (0, 0)
        judged = sub = 0
        for d in forbidden:
            truth = truth_ips.get(d)
            if not truth:
                continue           # глобальная правда по этому домену не получена
            judged += 1
            if not (_udp_ips(a, name, d) & truth):
                sub += 1           # расхождение или молчание (блок)
        return judged, sub

    def _subst_cell(name: str) -> str:
        """Колонка "Подмена" — строка на каждый UDP-адрес (как UDP мин)."""
        addrs = udp_by_name.get(name, [])
        if not addrs or not forbidden:
            return "[dim]—[/dim]"
        return "\n".join(_subst_line(a, name) for a in addrs)

    # ── Таблица ───────────────────────────────────────────────────────────────
    from rich.table import Table
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Провайдер", style="cyan", no_wrap=True, min_width=16)
    t.add_column("DoH мин", justify="right", no_wrap=True)
    if dot_servers:
        t.add_column("DoT мин", justify="right", no_wrap=True)
    t.add_column("UDP мин", justify="right", no_wrap=True)
    t.add_column("Реальный UDP резолвер", no_wrap=True)
    t.add_column("Подмена", justify="right", no_wrap=True)

    # Доступность считаем ПО СЕРВЕРАМ (а не по именам): N/M DoH и K/L UDP
    doh_ok_cnt = sum(
        1 for a, n, _ in doh_servers
        if any(v is not None for v in raw.get(("doh_wire", a, n), {}).values())
    )
    udp_ok_cnt = sum(
        1 for a, n, _ in udp_servers
        if any(raw.get(("udp", a, n), {}).get(d) is not None for d in allowed)
    )
    dot_ok_cnt = sum(
        1 for a, n, _ in dot_servers
        if any(v is not None for v in raw.get(("dot", a, n), {}).values())
    )

    for name in all_names:
        cells = [_latency_cell("doh_wire", name)]
        if dot_servers:
            cells.append(_latency_cell("dot", name))
        cells += [_latency_cell("udp", name), _egress_cell(name), _subst_cell(name)]
        n_rows = max((len(c.splitlines()) for c in cells), default=1)
        # Под-строки (дополнительные эндпоинты) — «Имя #N» вместо пустоты
        name_cell = "\n".join(name if i == 0 else f"{name} #{i + 1}"
                              for i in range(n_rows))
        t.add_row(name_cell, *cells)

    try:
        meas = t.__rich_measure__(console, console.options)
        wide = max(console.width, int(meas.maximum) + 2)
        # Общий console (с width на печать) — таблица попадает в экспорт [S]
        console.print(t, width=wide)
    except Exception:
        console.print(t)

    # Бренды провайдеров, чей реальный резолвер перехвачен (для сводки)
    hijacked_brands: list[str] = []
    hi_brand_set: set[str] = set()
    for hname, haddrs in udp_by_name.items():
        for ha in haddrs:
            heip = egress.get(("egress", ha, hname))
            if heip and heip != "0.0.0.0" and _is_hijacked(heip) \
                    and not _known_resolver(_org_label(heip)) \
                    and not _is_domestic(hname):
                hi_brand_set.add(_brand(hname))
    hijacked_brands = sorted(hi_brand_set)
    console.print()
    # Сколько всего резолверов (брендов) в тесте - для сводки "Все"
    resolvers_total = len({_brand(n) for n in udp_by_name
                           if not _is_domestic(n)})

    # Сводка по подмене: судимы только резолверы, где есть DoH-правда
    # ("пустые" — не судимые — не считаем)
    subst_sub = subst_total = 0
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            j, s = _subst_counts(sa, snm)
            if j:
                subst_total += 1
                if s:
                    subst_sub += 1

    # IP заглушек: UDP-ответы, расходящиеся с глобальной правдой
    stub_ip_counts: dict[str, int] = {}
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            if not _udp_server_available(sa, snm):
                continue
            for d in forbidden:
                truth = truth_ips.get(d)
                if not truth:
                    continue
                uips = _udp_ips(sa, snm, d)
                if uips and not (uips & truth):
                    for ip in uips:
                        stub_ip_counts[ip] = stub_ip_counts.get(ip, 0) + 1
    top_stub = max(stub_ip_counts, key=stub_ip_counts.get) if stub_ip_counts else None

    # Сколько судимых резолверов вернули FakeIP (прозрачный прокси)
    fakeip_sub = 0
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            j, _ = _subst_counts(sa, snm)
            if j and _fakeip_sub(sa, snm) > 0:
                fakeip_sub += 1
    fakeip_total = subst_total

    if subst_sub > 0:
        console.print()
        if top_stub and get_fake_ip_type(top_stub) == "fakeip":
            console.print(
                "[bold magenta][!] DNS-ответы содержат FakeIP[/bold magenta]\n"
                "Для честной оценки DNS отключите прокси/FakeIP на время проверки."
            )
        else:
            console.print(
                "[bold yellow][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold yellow]\n"
                "Провайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY/TIMEOUT\n"
                + (f"IP адрес заглушки провайдера - {top_stub}.\n" if top_stub else "")
                + "Рекомендация: настройте DoH на устройстве/роутере, если еще не сделали этого."
            )

    return {
        "doh_ok":          doh_ok_cnt,
        "doh_total":       len(doh_servers),
        "dot_ok":          dot_ok_cnt,
        "dot_total":       len(dot_servers),
        "udp_ok":          udp_ok_cnt,
        "udp_total":       len(udp_servers),
        "hijacked_brands": hijacked_brands,
        "resolvers_total": resolvers_total,
        "subst_sub":       subst_sub,
        "subst_total":     subst_total,
        "fakeip_sub":      fakeip_sub,
        "fakeip_total":    fakeip_total,
    }
