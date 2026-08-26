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
from utils.network import get_fake_ip_type, pin_ipv4
from utils.error_classifier import classify_connect_error, classify_read_error


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


async def check_dns_availability() -> dict:
    """
    Тест 1: доступность DNS-серверов + пинг + детект подмены.

    Двух-фазная схема (чтобы пинги и детект подмены не конфликтовали):
      Фаза A (UDP): доверенные домены (вне цензуры) — по ним меряем пинг
                    и считаем, что сервер вообще жив.
      Фаза B (UDP): если сервер жив — те же серверы опрашиваются по
                    запрещённым доменам; сравнение UDP-ответа с DoH-правдой
                    выявляет подмену. «Молчание» на запрещённом домене тоже
                    считается подменой (блок без ответа), а не недоступностью.

    DoH (Wire) сразу проверяет запрещённые домены — это эталон «правды»,
    с которым сравниваются UDP-ответы. Один TLS-коннект на сервер, запросы
    последовательно (фикс плоских 300мс ТСПУ).

    Таблица: Провайдер | DoH мин | UDP мин | Реальный резолвер | Подменяется?
    """
    servers = getattr(config, "DNS_AVAILABILITY_SERVERS", [])
    # Доверенные домены (не под цензурой) — по ним пинг и доступность
    allowed = getattr(config, "DNS_AVAILABILITY_DOMAINS", ["vk.ru", "gosuslugi.ru"])
    # Запрещённые домены (из теста 1) — по ним выявляем подмену
    forbidden = getattr(config, "DNS_CHECK_DOMAINS", [])
    timeout = getattr(config, "DNS_AVAILABILITY_TIMEOUT", config.DNS_CHECK_TIMEOUT)

    if not servers:
        console.print("[yellow]DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.[/yellow]")
        return {"doh_ok": 0, "doh_total": 0, "udp_ok": 0, "udp_total": 0,
                "hijacked_brands": []}

    proxy_url = getattr(config, "PROXY_URL", None)

    # ── Группируем серверы ────────────────────────────────────────────────────
    udp_servers  = [(a, n) for a, n, k in servers if k == "udp"]
    wire_servers = [(a, n) for a, n, k in servers if k == "doh_wire"]
    doh_servers  = wire_servers  # только Wire

    # ── Уникальные имена провайдеров в порядке появления ─────────────────────
    all_names: list[str] = []
    seen: set[str] = set()
    for _, n in (doh_servers + udp_servers):
        if n not in seen:
            all_names.append(n)
            seen.add(n)

    doh_by_name: dict[str, list[str]] = {}
    udp_by_name: dict[str, list[str]] = {}
    for a, n in doh_servers:
        doh_by_name.setdefault(n, []).append(a)
    for a, n in udp_servers:
        udp_by_name.setdefault(n, []).append(a)

    # ── Заголовок ─────────────────────────────────────────────────────────────
    console.print(
        f"\n[bold]Проверка доступности DNS-серверов[/bold]  "
        f"[dim]DoH: {len(doh_servers)} | UDP: {len(udp_servers)}"
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
    ep_table.add_column("UDP",            style="dim",   no_wrap=True)

    for name in all_names:
        doh_urls = doh_by_name.get(name, [])
        udp_ips  = udp_by_name.get(name, [])
        doh_str  = "\n".join(doh_urls) if doh_urls else "[dim]—[/dim]"
        udp_str  = ", ".join(udp_ips)   if udp_ips  else "[dim]—[/dim]"
        ep_table.add_row(name, doh_str, udp_str)

    console.print(ep_table)
    console.print()

    # ── Домены проверки и дисклеймер ──────────────────────────────────────────
    console.print(
        f"[bold]Заблокированные домены для проверки:[/bold] {', '.join(forbidden)}\n"
        f"[bold]Незаблокированные домены для проверки:[/bold] {', '.join(allowed)}\n"
        "[bold yellow]ВНИМАНИЕ:[/bold yellow] Это независимая проверка и она не использует ваши настроенные DNS!"
    )

    # ── Счётчик прогресса ─────────────────────────────────────────────────────
    total_probes  = len(doh_servers) + len(udp_servers)
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

    # ── UDP probe: фаза A (доверенные) → фаза B (запрещённые, если жив) ──────
    async def _probe_udp(addr: str, name: str) -> None:
        key = ("udp", addr, name)
        loop = asyncio.get_running_loop()
        udp_sem = asyncio.Semaphore(15)  # Ограничиваем кол-во одновременных сокетов

        async def _wait(domain: str):
            async with udp_sem:
                q = _build_dns_query(domain)
                tx_id = q[:2]
                fut = loop.create_future()
                transport = None
                t0 = time.perf_counter()
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _SingleQueryProto(fut), remote_addr=(addr, 53)
                    )
                    transport.sendto(q)
                    data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
                    elapsed_ms = round((t_recv - t0) * 1000, 1)
                    parsed = _parse_dns_response(data, tx_id)
                    ok = isinstance(parsed, list)   # «успех» — только с реальными IP
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
        doh_sem = asyncio.Semaphore(20)

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

    # ── DoH Wire probe: эталон «правды» по запрещённым доменам ───────────────
    # Один клиент на сервер, один TLS-коннект, боевые запросы последовательно
    # (иначе каждый открывает своё соединение и платит +300мс ТСПУ).
    async def _probe_doh_wire(addr: str, name: str) -> None:
        key = ("doh_wire", addr, name)
        orig_addr = addr   # адрес до пининга — по нему храню ответы (совпадает с doh_by_name)
        # Привязка к IPv4: коннект по A-записи, SNI и Host — от имени сервера
        addr, ehost = await pin_ipv4(addr)
        ehost_headers = {"Host": ehost} if ehost else {}
        ehost_ext = {"sni_hostname": ehost} if ehost else None
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(20)
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

    # ── Запускаем: только Wire + UDP ─────────────────────────────────────────
    probe_gate = asyncio.Semaphore(getattr(config, "DNS_PROBE_CONCURRENCY", 3))

    # ── Выходной резолвер: A whoami.akamai.net ────────────────────────────────
    egress: dict[tuple, Optional[str]] = {}

    async def _probe_egress(addr: str, name: str) -> None:
        key = ("egress", addr, name)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        transport = None
        try:
            q = _build_dns_query("whoami.akamai.net")
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SingleQueryProto(fut), remote_addr=(addr, 53)
            )
            transport.sendto(q)
            data, _t = await asyncio.wait_for(fut, timeout=timeout)
            parsed = _parse_dns_response(data, q[:2])
            egress[key] = parsed[0] if isinstance(parsed, list) and parsed else None
        except Exception:
            egress[key] = None
        finally:
            if transport:
                transport.close()

    async def _probe_udp_gated(addr, name):
        async with probe_gate:
            await _probe_udp(addr, name)

    async def _probe_doh_wire_gated(addr, name):
        async with probe_gate:
            await _probe_doh_wire(addr, name)

    egress_sem = asyncio.Semaphore(10)

    async def _probe_egress_gated(addr, name):
        async with egress_sem:
            await _probe_egress(addr, name)

    _redraw_progress()
    if udp_servers:
        await asyncio.gather(
            *[_probe_udp_gated(a, n) for a, n in udp_servers]
          + [_probe_egress_gated(a, n) for a, n in udp_servers]
        )

    if wire_servers:
        await asyncio.gather(*[_probe_doh_wire_gated(a, n) for a, n in wire_servers])

    import sys
    sys.stderr.write(f"\r  Проверено серверов: {done_count}/{total_probes}          \n")
    sys.stderr.flush()

    # ── Имена организаций выходных IP (Team Cymru через DoH) ──────────────────
    _CYMRU_DOH = ("https://cloudflare-dns.com/dns-query",
                  "https://dns.google/resolve")

    def _doh_txt_fields(txt: str) -> list:
        return [p.strip() for p in txt.strip('"').split("|")]

    async def _lookup_asn_name(client: httpx.AsyncClient, ip: str) -> Optional[str]:
        if ip.count(".") != 3:
            return None
        rev = ".".join(reversed(ip.split(".")))
        asn = None
        for url, ehost in [await pin_ipv4(u) for u in _CYMRU_DOH]:
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
        for url, ehost in [await pin_ipv4(u) for u in _CYMRU_DOH]:
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

    _ASN_CACHE_FILE = os.path.join(tempfile.gettempdir(), "dpi_detector_asn_cache.json")

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
        sem = asyncio.Semaphore(8)
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

    org_names = await _resolve_asn_names()

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
        addrs = (udp_by_name if kind == "udp" else doh_by_name).get(name, [])
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
        addrs = (udp_by_name if kind == "udp" else doh_by_name).get(name, [])
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
            elif _is_hijacked(eip):
                lines.append(f"[red]{a}→{_org_label(eip)}[/red]")
            else:
                lines.append(f"[green]{a}→{_org_label(eip)}[/green]")
        return "\n".join(lines)

    # ── Глобальная правда по запрещённым доменам (из любого чистого DoH) ───────
    # Все UDP-ответы сравниваются с ЭТИМ единым набором IP, а не с DoH конкретного
    # провайдера. Так проверяются и серверы без своего DoH (MSK-IX, НСДИ, dnsforge...).
    TRUTH_DOH = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
        "https://dns.quad9.net/dns-query",
    ]

    async def _fetch_truth() -> dict[str, set]:
        truth: dict[str, set] = {}
        if not forbidden:
            return truth
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)

        async def _resolve(endpoint: str) -> dict[str, set]:
            out: dict[str, set] = {}
            try:
                url, ehost = await pin_ipv4(endpoint)
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
        """Колонка «Подменяется?» — строка на каждый UDP-адрес (как UDP мин)."""
        addrs = udp_by_name.get(name, [])
        if not addrs or not forbidden:
            return "[dim]—[/dim]"
        return "\n".join(_subst_line(a, name) for a in addrs)

    # ── Таблица ───────────────────────────────────────────────────────────────
    from rich.table import Table
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Провайдер", style="cyan", no_wrap=True, min_width=16)
    t.add_column("DoH мин", justify="right", no_wrap=True)
    t.add_column("UDP мин", justify="right", no_wrap=True)
    t.add_column("Реальный резолвер", no_wrap=True)
    t.add_column("Подменяется?", justify="right", no_wrap=True)

    # Доступность считаем ПО СЕРВЕРАМ (а не по именам): N/M DoH и K/L UDP
    doh_ok_cnt = sum(
        1 for a, n in doh_servers
        if any(v is not None for v in raw.get(("doh_wire", a, n), {}).values())
    )
    udp_ok_cnt = sum(
        1 for a, n in udp_servers
        if any(raw.get(("udp", a, n), {}).get(d) is not None for d in allowed)
    )

    for name in all_names:
        t.add_row(
            name,
            _latency_cell("doh_wire", name),
            _latency_cell("udp", name),
            _egress_cell(name),
            _subst_cell(name),
        )

    try:
        meas = t.__rich_measure__(console, console.options)
        wide = max(console.width, int(meas.maximum) + 2)
        from rich.console import Console as _WideConsole
        _WideConsole(file=sys.stdout, width=wide).print(t)
    except Exception:
        console.print(t)

    # Бренды провайдеров, чей реальный резолвер перехвачен (для сводки)
    hijacked_brands: list[str] = []
    hi_brand_set: set[str] = set()
    for hname, haddrs in udp_by_name.items():
        for ha in haddrs:
            heip = egress.get(("egress", ha, hname))
            if heip and heip != "0.0.0.0" and _is_hijacked(heip) \
                    and not _is_domestic(hname):
                hi_brand_set.add(_brand(hname))
    hijacked_brands = sorted(hi_brand_set)
    console.print()

    # Сводка по подмене: судимы только резолверы, где есть DoH-правда
    # («пустые» — не судимые — не считаем)
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
        "udp_ok":          udp_ok_cnt,
        "udp_total":       len(udp_servers),
        "hijacked_brands": hijacked_brands,
        "subst_sub":       subst_sub,
        "subst_total":     subst_total,
        "fakeip_sub":      fakeip_sub,
        "fakeip_total":    fakeip_total,
    }
