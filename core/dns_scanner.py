import os
import struct
import socket
import asyncio
import base64
import time
from typing import Tuple, List, Union, Optional
import httpx
from utils import config
from cli.console import console
from utils.network import get_fake_ip_type


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


# ── Single-domain probes ─────────────────────────────────────────────────────
async def _probe_udp_single(nameserver: str, domain: str) -> Optional[List[str]]:
    """UDP DNS — один домен (до 2 попыток)."""
    for attempt in range(2):
        try:
            res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
            if isinstance(res, list):
                return res
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(0.5)
    return None

async def _probe_doh_json_single(doh_url: str, domain: str) -> Optional[List[str]]:
    """DoH JSON API (?name=…&type=A) — один домен (до 2 попыток)."""
    headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}
    for attempt in range(2):
        try:
            proxy_url = getattr(config, "PROXY_URL", None)
            async with httpx.AsyncClient(
                timeout=config.DNS_CHECK_TIMEOUT, verify=False,
                headers=headers, proxy=proxy_url, trust_env=False
            ) as client:
                resp = await client.get(doh_url, params={"name": domain, "type": "A"})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("Status") != 3:  # Не NXDOMAIN
                        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                        if ips:
                            return ips
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(0.5)
    return None

async def _probe_doh_wire_single(doh_url: str, domain: str) -> Optional[List[str]]:
    """DoH wire-format (RFC 8484) — один домен (до 2 попыток)."""
    query = _build_dns_query(domain)
    tx_id = query[:2]
    for attempt in range(2):
        try:
            proxy_url = getattr(config, "PROXY_URL", None)
            async with httpx.AsyncClient(
                timeout=config.DNS_CHECK_TIMEOUT, verify=False,
                proxy=proxy_url, trust_env=False, http2=True
            ) as client:
                resp = await client.post(
                    doh_url, content=query,
                    headers={
                        "Content-Type": "application/dns-message",
                        "Accept": "application/dns-message",
                        "User-Agent": config.USER_AGENT,
                    },
                )
                if resp.status_code != 200:
                    dns_b64 = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
                    resp = await client.get(
                        doh_url, params={"dns": dns_b64},
                        headers={
                            "Accept": "application/dns-message",
                            "User-Agent": config.USER_AGENT,
                        },
                    )
                if resp.status_code == 200:
                    result = _parse_dns_response(resp.content, tx_id)
                    if isinstance(result, list):
                        return result
        except Exception:
            pass
        if attempt == 0:
            await asyncio.sleep(0.5)
    return None


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
            results[domain] = "ERROR"
            error += 1

    return {"ok": ok, "timeout": timeout_cnt, "error": error, "results": results}


async def _probe_doh_json_all(doh_url: str, domains: list) -> dict:
    """Параллельно резолвит все домены через DoH JSON API."""
    headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}

    async def _query(client, domain):
        try:
            resp = await client.get(doh_url, params={"name": domain, "type": "A"})
            if resp.status_code != 200:
                return domain, "BLOCKED", None
            data = resp.json()
            if data.get("Status") == 3:
                return domain, "NXDOMAIN", None
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            return domain, "OK", ips if ips else "EMPTY"
        except httpx.TimeoutException:
            return domain, "TIMEOUT", None
        except Exception:
            return domain, "BLOCKED", None

    proxy_url = getattr(config, "PROXY_URL", None)
    async with httpx.AsyncClient(
        timeout=config.DNS_CHECK_TIMEOUT, verify=False,
        headers=headers, proxy=proxy_url, trust_env=False,
    ) as client:
        completed = await asyncio.gather(*[_query(client, d) for d in domains])

    ok = timeout_cnt = blocked = 0
    results = {}
    for domain, status, res in completed:
        if status in ("OK", "NXDOMAIN"):
            results[domain] = res if status == "OK" else "NXDOMAIN"
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            results[domain] = "BLOCKED"
            blocked += 1

    return {"ok": ok, "timeout": timeout_cnt, "blocked": blocked, "results": results}


async def _probe_doh_wire_all(doh_url: str, domains: list) -> dict:
    """Параллельно резолвит все домены через DoH wire-format (RFC 8484)."""

    async def _query(client, domain):
        try:
            query = _build_dns_query(domain)
            tx_id = query[:2]

            # ── POST ──
            resp = await client.post(
                doh_url, content=query,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                    "User-Agent": config.USER_AGENT,
                },
            )
            if resp.status_code != 200:
                # ── GET fallback ──
                dns_b64 = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
                resp = await client.get(
                    doh_url, params={"dns": dns_b64},
                    headers={
                        "Accept": "application/dns-message",
                        "User-Agent": config.USER_AGENT,
                    },
                )
                if resp.status_code != 200:
                    return domain, "BLOCKED", None

            result = _parse_dns_response(resp.content, tx_id)
            if result == "NXDOMAIN":
                return domain, "NXDOMAIN", None
            if isinstance(result, list):
                return domain, "OK", result
            return domain, "EMPTY", None
        except httpx.TimeoutException:
            return domain, "TIMEOUT", None
        except Exception:
            return domain, "BLOCKED", None

    proxy_url = getattr(config, "PROXY_URL", None)
    async with httpx.AsyncClient(
        timeout=config.DNS_CHECK_TIMEOUT, verify=False,
        proxy=proxy_url, trust_env=False, http2=True
    ) as client:
        completed = await asyncio.gather(*[_query(client, d) for d in domains])

    ok = timeout_cnt = blocked = 0
    results = {}
    for domain, status, res in completed:
        if status in ("OK", "NXDOMAIN"):
            results[domain] = res if status == "OK" else "NXDOMAIN"
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            results[domain] = "BLOCKED"
            blocked += 1

    return {"ok": ok, "timeout": timeout_cnt, "blocked": blocked, "results": results}


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


# ── Тест 1: Проверка подмены DNS ─────────────────────────────────────────────

async def check_dns_integrity() -> Tuple[set, int, bool]:
    total = len(config.DNS_CHECK_DOMAINS)
    probe_domain = config.DNS_CHECK_DOMAINS[0]

    console.print(
        f"\n[bold]Проверка подмены DNS[/bold]  "
        f"[dim]Целей: {total} | timeout: {config.DNS_CHECK_TIMEOUT}s[/dim]"
    )
    console.print("[dim]Проверяем, перехватывает ли провайдер DNS запросы...[/dim]\n")

    # ── Списки серверов ───────────────────────────────────────────────────────
    udp_servers      = config.DNS_UDP_SERVERS               # [(ip, name)]
    doh_json_servers = config.DNS_DOH_SERVERS               # [(url, name)] — JSON API
    doh_wire_servers = getattr(config, 'DNS_DOH_WIRE_SERVERS', [])  # [(url, name)] — RFC 8484

    # ── Фаза 1: быстрый параллельный пинг одним доменом ──────────────────────
    async def _qp_udp(ip, n):
        return ip, n, await _probe_udp_single(ip, probe_domain)

    async def _qp_json(u, n):
        return u, n, await _probe_doh_json_single(u, probe_domain)

    async def _qp_wire(u, n):
        return u, n, await _probe_doh_wire_single(u, probe_domain)

    quick = await asyncio.gather(
        *[_qp_udp(ip, n)  for ip, n in udp_servers],
        *[_qp_json(u, n)  for u, n  in doh_json_servers],
        *[_qp_wire(u, n)  for u, n  in doh_wire_servers],
    )

    n_u, n_j = len(udp_servers), len(doh_json_servers)
    udp_quick  = quick[:n_u]
    json_quick = quick[n_u:n_u + n_j]
    wire_quick = quick[n_u + n_j:]

    # ── Фаза 2: полный тест для «молчащих» серверов ──────────────────────────
    async def _full_udp(ip, n):
        p = await _probe_udp_all(ip, config.DNS_CHECK_DOMAINS)
        return ip, n, p["ok"] > 0

    async def _full_json(u, n):
        p = await _probe_doh_json_all(u, config.DNS_CHECK_DOMAINS)
        return u, n, p["ok"] > 0

    async def _full_wire(u, n):
        p = await _probe_doh_wire_all(u, config.DNS_CHECK_DOMAINS)
        return u, n, p["ok"] > 0

    need_u = [(k, n) for k, n, r in udp_quick  if r is None]
    need_j = [(k, n) for k, n, r in json_quick if r is None]
    need_w = [(k, n) for k, n, r in wire_quick if r is None]

    full_u = full_j = full_w = {}

    if need_u or need_j or need_w:
        done = await asyncio.gather(
            *[_full_udp(k, n)  for k, n in need_u],
            *[_full_json(k, n) for k, n in need_j],
            *[_full_wire(k, n) for k, n in need_w],
        )
        nu, nj = len(need_u), len(need_j)
        full_u = {(k, n): ok for k, n, ok in done[:nu]}
        full_j = {(k, n): ok for k, n, ok in done[nu:nu + nj]}
        full_w = {(k, n): ok for k, n, ok in done[nu + nj:]}

    # ── Классификация серверов ────────────────────────────────────────────────
    def _classify(quick_list, full_map, label):
        working, log = [], []
        for key, name, qr in quick_list:
            if qr is not None or full_map.get((key, name), False):
                working.append((key, name))
            else:
                log.append(f"[dim]• {label} [yellow]{key} ({name})[/yellow] недоступен[/dim]")
        return working, log

    udp_working, udp_log   = _classify(udp_quick,  full_u, "UDP")
    json_working, json_log = _classify(json_quick, full_j, "DoH JSON")
    wire_working, wire_log = _classify(wire_quick, full_w, "DoH Wire")

    all_log = udp_log + json_log + wire_log
    if all_log:
        for line in all_log:
            console.print(line)
        console.print()

    # ── Выбор по одному серверу каждого типа ─────────────────────────────────
    def _pick(working, all_list):
        if not working:
            return None, None
        first = all_list[0][0]
        for k, n in working:
            if k == first:
                return k, n
        return working[0]

    udp_key,  udp_name  = _pick(udp_working,  udp_servers)
    json_key, json_name = _pick(json_working, doh_json_servers)
    wire_key, wire_name = (
        _pick(wire_working, doh_wire_servers) if doh_wire_servers else (None, None)
    )

    # ── Полный тест выбранными серверами ──────────────────────────────────────
    _unavail = lambda: {"results": {d: "UNAVAIL" for d in config.DNS_CHECK_DOMAINS}}

    # UDP
    if udp_key:
        console.print(f"[dim]UDP: [cyan]{udp_key} ({udp_name})[/cyan][/dim]")
        udp_probe = await _probe_udp_all(udp_key, config.DNS_CHECK_DOMAINS)
        udp_label = f"UDP {udp_key}"
    else:
        console.print("[red]× Все UDP DNS-серверы недоступны[/red]")
        udp_probe = _unavail()
        udp_label = "UDP (—)"

    # DoH JSON
    if json_key:
        console.print(f"[dim]DoH JSON: [cyan]{json_key} ({json_name})[/cyan][/dim]")
        json_probe = await _probe_doh_json_all(json_key, config.DNS_CHECK_DOMAINS)
        json_label = f"DoH JSON ({json_name})"
    else:
        console.print("[red]× Все DoH JSON-серверы недоступны[/red]")
        json_probe = _unavail()
        json_label = "DoH JSON (—)"

    # DoH Wire (RFC 8484)
    has_wire = bool(doh_wire_servers)
    if has_wire:
        if wire_key:
            console.print(
                f"[dim]DoH Wire [italic](RFC 8484)[/italic]: "
                f"[cyan]{wire_key} ({wire_name})[/cyan][/dim]"
            )
            wire_probe = await _probe_doh_wire_all(wire_key, config.DNS_CHECK_DOMAINS)
            wire_label = f"DoH Wire ({wire_name})"
        else:
            console.print("[red]× Все DoH Wire-серверы (RFC 8484) недоступны[/red]")
            wire_probe = _unavail()
            wire_label = "DoH Wire (—)"
    else:
        wire_probe = None
        wire_label = ""

    console.print()

    # ── Анализ результатов ────────────────────────────────────────────────────
    dns_intercept_count = doh_blocked_count = 0
    udp_ips_collection: dict = {}
    rows = []

    for domain in config.DNS_CHECK_DOMAINS:
        udp_res  = udp_probe["results"].get(domain)
        json_res = json_probe["results"].get(domain)
        wire_res = wire_probe["results"].get(domain) if wire_probe else None

        udp_ips  = udp_res  if isinstance(udp_res, list)  else None
        json_ips = json_res if isinstance(json_res, list) else None
        wire_ips = wire_res if isinstance(wire_res, list) else None

        if udp_ips:
            udp_ips_collection[domain] = udp_ips

        udp_str  = ", ".join(udp_ips[:2])  if udp_ips  else str(udp_res  or "—")
        json_str = ", ".join(json_ips[:2]) if json_ips else str(json_res or "—")
        wire_str = (
            ", ".join(wire_ips[:2]) if wire_ips else str(wire_res or "—")
        ) if has_wire else None

        if json_res == "BLOCKED":
            doh_blocked_count += 1
        if has_wire and wire_res == "BLOCKED":
            doh_blocked_count += 1

        # Доверенные IP = объединение ответов обоих DoH-методов
        trusted = set()
        if json_ips:
            trusted.update(json_ips)
        if wire_ips:
            trusted.update(wire_ips)

        # Проверяем, вернул ли UDP адрес Fake-IP
        udp_is_fakeip = False
        if udp_ips:
            for ip in udp_ips:
                if get_fake_ip_type(ip) == "fakeip":
                    udp_is_fakeip = True
                    break

        # ── Определяем статус ─────────────────────────────────────────────
        if trusted and udp_ips:
            if set(udp_ips) & trusted:                    # есть пересечение → ОК
                row_status = "[green]√ DNS OK[/green]"
            elif udp_is_fakeip:                           # это FakeIP от VPN
                row_status = "[green]√ FAKE-IP[/green]"
            else:
                row_status = "[red]× DNS ПОДМЕНА[/red]"
                dns_intercept_count += 1
        elif trusted and not udp_ips:
            labels = {
                "TIMEOUT":  "[red]× DNS ПЕРЕХВАТ[/red]",
                "NXDOMAIN": "[red]× FAKE NXDOMAIN[/red]",
                "EMPTY":    "[red]× FAKE EMPTY[/red]",
                "UNAVAIL":  "[yellow]× UDP недоступен[/yellow]",
            }
            row_status = labels.get(str(udp_res), "[red]× UDP БЛОК[/red]")
            if udp_res != "UNAVAIL":
                dns_intercept_count += 1
        elif udp_ips and not trusted:
            is_blocked = (
                json_res == "BLOCKED"
                or (has_wire and wire_res == "BLOCKED")
            )
            reason = "заблокирован" if is_blocked else "недоступен"
            row_status = f"[red]× DoH {reason}[/red]"
            if not udp_is_fakeip:
                dns_intercept_count += 1
        else:
            row_status = "[red]× Оба недоступны[/red]"
            dns_intercept_count += 1

        # Строка таблицы
        if has_wire:
            rows.append([domain, json_str, wire_str, udp_str, row_status])
        else:
            rows.append([domain, json_str, udp_str, row_status])

    # ── Заглушки ──────────────────────────────────────────────────────────────
    ip_count: dict = {}
    for ips in udp_ips_collection.values():
        for ip in ips:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    stub_ips = {ip for ip, cnt in ip_count.items() if cnt >= 2}

    # ── Таблица ───────────────────────────────────────────────────────────────
    from rich.table import Table
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Домен", style="cyan")
    t.add_column(json_label, style="dim")
    if has_wire:
        t.add_column(wire_label, style="dim")
    t.add_column(udp_label, style="dim")
    t.add_column("Статус")
    for row in rows:
        t.add_row(*row)
    console.print(t)
    console.print()

    # ── Диагностика ───────────────────────────────────────────────────────────
    if dns_intercept_count > 0:
        console.print("[bold red][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold red]")
        console.print(
            "Провайдер подменяет ответы UDP DNS на заглушки "
            "или ложные NXDOMAIN/EMPTY\n"
        )
        console.print(
            "[bold yellow]ВНИМАНИЕ: Это независимая проверка и она не использует "
            "ваши настроенные DNS![/bold yellow]\n"
            "[bold yellow]Рекомендация:[/bold yellow] Настройте DoH на устройстве и роутере\n"
            "[bold green]Если DoH уже настроен — игнорируйте эту проверку.[/bold green]\n"
        )
    if doh_blocked_count > 0:
        console.print(
            "[bold red][!] DoH заблокирован[/bold red] — "
            "провайдер блокирует зашифрованный DNS\n"
        )

    all_doh_unavailable = not bool(json_working) and not bool(wire_working)
    return stub_ips, dns_intercept_count, all_doh_unavailable


# ── Тест 2: Проверка доступности DNS-серверов ────────────────────────────────

async def check_dns_availability() -> dict:
    """
    Тест 2: Проверяет доступность DNS-серверов и замеряет время резолва.

    Использует только DoH Wire (RFC 8484) — метод _probe_doh_json оставлен
    для возможного использования, но не вызывается.

    Вывод:
      1. Список эндпоинтов по именам
      2. Прогресс-строка (обновляется в процессе проверки)
      3. Сводная таблица: Провайдер | DoH avg | UDP avg
         — прочерк = нет сервера этого типа
         — TIMEOUT  = сервер есть, но все запросы провалились
         — Nмс [k/n] = среднее по успешным; k/n если не все ответили
      4. Возвращает dict с итогами для _format_summary

    Правило таймингов: каждый DoH-сервер получает свой изолированный
    httpx.AsyncClient — честный замер без конкуренции за пул соединений.
    """
    servers = getattr(config, "DNS_AVAILABILITY_SERVERS", [])
    domains = getattr(config, "DNS_AVAILABILITY_DOMAINS", config.DNS_CHECK_DOMAINS)
    timeout = getattr(config, "DNS_AVAILABILITY_TIMEOUT", config.DNS_CHECK_TIMEOUT)

    if not servers:
        console.print("[yellow]DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.[/yellow]")
        return {"doh_ok": 0, "doh_total": 0, "udp_ok": 0, "udp_total": 0}

    proxy_url = getattr(config, "PROXY_URL", None)

    # ── Группируем серверы ────────────────────────────────────────────────────
    udp_servers  = [(a, n) for a, n, k in servers if k == "udp"]
    # doh_json_servers — оставлены для возможного использования, но не запускаются
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
        f" | Доменов: {len(domains)} | timeout: {timeout}s[/dim]"
    )
    console.print()

    # ── Таблица эндпоинтов ────────────────────────────────────────────────────
    from rich.table import Table as _Table
    ep_table = _Table(show_header=True, header_style="bold magenta",
                      border_style="dim", box=None, pad_edge=False)
    ep_table.add_column("Провайдер", style="bold cyan", no_wrap=True, min_width=16)
    ep_table.add_column("DoH эндпоинты",  style="dim",   no_wrap=False)
    ep_table.add_column("UDP",            style="dim",   no_wrap=True)

    for name in all_names:
        doh_urls = doh_by_name.get(name, [])
        udp_ips  = udp_by_name.get(name, [])
        doh_str  = "\n".join(doh_urls) if doh_urls else "[dim]—[/dim]"
        udp_str  = ", ".join(udp_ips)   if udp_ips  else "[dim]—[/dim]"
        ep_table.add_row(name, doh_str, udp_str)

    console.print(ep_table)
    console.print()

    # ── Счётчик прогресса ─────────────────────────────────────────────────────
    total_probes  = len(doh_servers) + len(udp_servers)
    done_count    = 0
    progress_lock = asyncio.Lock()

    def _redraw_progress():
        # \r без \n — перезаписывает текущую строку
        import sys
        bar = f"  Проверка серверов... {done_count}/{total_probes}"
        sys.stderr.write(f"\r{bar}   ")
        sys.stderr.flush()

    async def _tick():
        nonlocal done_count
        async with progress_lock:
            done_count += 1
            _redraw_progress()

    # ── raw[(kind, addr, name)][domain] = elapsed_ms or None ─────────────────
    # None = сервер есть, но запрос не прошёл (TIMEOUT/ERR/NXDOMAIN)
    # Ключ отсутствует = этот тип у данного имени не определён
    raw: dict[tuple, dict[str, Optional[int]]] = {}

    # ── UDP probe ─────────────────────────────────────────────────────────────
    # Фиксы:
    # 1. t_recv снимается прямо в datagram_received (до event-loop планировщика)
    # 2. pending[tid] записывается ДО sendto — нет race condition
    # 3. tid из инкрементного счётчика — нет коллизий os.urandom(2)
    # 4. Семафор ограничивает параллельный залп (защита от packet drop)
    async def _probe_udp(addr: str, name: str) -> None:
        key = ("udp", addr, name)
        loop = asyncio.get_running_loop()
        udp_sem = asyncio.Semaphore(15) # Ограничиваем кол-во одновременных сокетов

        # Выносим класс протокола наружу, чтобы передавать ему конкретный future
        class _SingleQueryProto(asyncio.DatagramProtocol):
            def __init__(self, fut):
                self.fut = fut

            def datagram_received(self, data, _addr):
                # Идеально точное время прямо в момент получения пакета ОС
                t_recv = time.perf_counter()
                if not self.fut.done():
                    self.fut.set_result((data, t_recv))

            def error_received(self, exc):
                pass

            def connection_lost(self, exc):
                err = exc or ConnectionError("Socket closed")
                if not self.fut.done():
                    self.fut.set_exception(err)

        async def _wait(domain: str) -> tuple[str, Optional[float]]:
            async with udp_sem:
                q = _build_dns_query(domain)
                tx_id = q[:2]
                fut = loop.create_future()
                transport = None
                t0 = time.perf_counter()

                try:
                    # Создаем уникальный сокет для каждого домена
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _SingleQueryProto(fut), remote_addr=(addr, 53)
                    )
                    transport.sendto(q)

                    data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
                    elapsed_ms = round((t_recv - t0) * 1000, 1)
                    parsed = _parse_dns_response(data, tx_id)

                    return domain, elapsed_ms if isinstance(parsed, list) else None
                except Exception:
                    return domain, None
                finally:
                    if transport:
                        transport.close()

        pairs = await asyncio.gather(*[_wait(d) for d in domains])
        raw[key] = dict(pairs)
        await _tick()

    # ── DoH JSON probe ────────────────────────────────────────────────────────
    # Один клиент на сервер — один TLS handshake.
    # Прогревочный запрос исключает handshake из замера боевых запросов.
    async def _probe_doh_json(addr: str, name: str) -> None:
        key = ("doh_json", addr, name)
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(20)

        async def _one(domain: str, client: httpx.AsyncClient) -> tuple[str, Optional[float]]:
            async with doh_sem:
                t0 = time.perf_counter()
                try:
                    resp = await client.get(addr, params={"name": domain, "type": "A"})
                    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                    if resp.status_code != 200:
                        return domain, None
                    data = resp.json()
                    if data.get("Status") == 3:
                        return domain, None
                    ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                    return domain, elapsed_ms if ips else None
                except Exception:
                    return domain, None

        try:
            async with httpx.AsyncClient(
                timeout=cli_timeout, verify=False,
                headers={"Accept": "application/dns-json", "User-Agent": config.USER_AGENT},
                proxy=proxy_url, trust_env=False,
            ) as client:
                # Прогрев — устанавливаем TLS-соединение до боевых замеров
                try:
                    warmup_q = domains[0] if domains else "google.com"
                    await client.get(addr, params={"name": warmup_q, "type": "A"})
                except Exception:
                    pass
                pairs = await asyncio.gather(*[_one(d, client) for d in domains])
        except Exception:
            pairs = [(d, None) for d in domains]
        raw[key] = dict(pairs)
        await _tick()

    # ── DoH Wire probe ────────────────────────────────────────────────────────
    # Один клиент на сервер. http2=True → ALPN.
    # Прогрев исключает TLS handshake из замера.
    # Fallback POST→GET сбрасывает таймер — замеряется только успешный метод.
    # ── DoH Wire probe ────────────────────────────────────────────────────────
    async def _probe_doh_wire(addr: str, name: str) -> None:
        key = ("doh_wire", addr, name)
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(20)

        # Выносим всю логику во внутреннюю функцию, чтобы обернуть её в жесткий таймаут
        async def _do_probe() -> list:
            async def _one(domain: str, client: httpx.AsyncClient) -> tuple[str, Optional[float]]:
                async with doh_sem:
                    query = _build_dns_query(domain)
                    tx_id = query[:2]
                    try:
                        t0 = time.perf_counter()
                        resp = await client.post(
                            addr, content=query,
                            headers={
                                "Content-Type": "application/dns-message",
                                "Accept":       "application/dns-message",
                                "User-Agent":   config.USER_AGENT,
                            },
                        )
                        if resp.status_code != 200:
                            dns_b64 = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
                            t0 = time.perf_counter()
                            resp = await client.get(
                                addr, params={"dns": dns_b64},
                                headers={"Accept": "application/dns-message",
                                         "User-Agent": config.USER_AGENT},
                            )
                        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                        if resp.status_code != 200:
                            return domain, None
                        result = _parse_dns_response(resp.content, tx_id)
                        return domain, elapsed_ms if isinstance(result, list) else None
                    except Exception:
                        return domain, None

            try:
                async with httpx.AsyncClient(
                    timeout=cli_timeout, verify=False,
                    proxy=proxy_url, trust_env=False, http2=True,
                ) as client:
                    # 1. Прогрев с Fail-Fast (Защита от двойного таймаута)
                    try:
                        warmup = _build_dns_query(domains[0] if domains else "google.com")
                        await client.post(
                            addr, content=warmup,
                            headers={"Content-Type": "application/dns-message",
                                     "Accept": "application/dns-message",
                                     "User-Agent": config.USER_AGENT},
                        )
                    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException):
                        # Сервер физически недоступен. Нет смысла спамить боевыми запросами.
                        return [(d, None) for d in domains]
                    except Exception:
                        pass # Сервер жив, но вернул 400/500 — продолжаем (м.б. GET сработает)

                    # 2. Боевые запросы (запустятся только если сервер жив)
                    return await asyncio.gather(*[_one(d, client) for d in domains])
            except Exception:
                return [(d, None) for d in domains]

        # 3. Жесткая гильотина: ограничиваем всё время проверки провайдера
        try:
            # Даем времени чуть больше, чтобы httpx успел закрыться сам штатно
            pairs = await asyncio.wait_for(_do_probe(), timeout=timeout + 2.0)
            raw[key] = dict(pairs)
        except (asyncio.TimeoutError, Exception):
            raw[key] = {d: None for d in domains}
        finally:
            await _tick()

    # ── Запускаем: только Wire + UDP ─────────────────────────────────────────
    _redraw_progress()
    if udp_servers:
        await asyncio.gather(*[_probe_udp(a, n) for a, n in udp_servers])

    if wire_servers:
        await asyncio.gather(*[_probe_doh_wire(a, n) for a, n in wire_servers])

    # Завершаем прогресс-строку — переходим на новую строку
    import sys
    sys.stderr.write(f"\r  Проверено серверов: {done_count}/{total_probes}          \n")
    sys.stderr.flush()

    # ── Агрегируем по имени провайдера ────────────────────────────────────────
    # Возвращает (avg_ms, ok, total) или ("TIMEOUT", 0, total) если сервер есть
    # но все провалились, или None если нет серверов этого типа вообще.
    def _aggregate(name: str, kind: str) -> Optional[tuple]:
        entries = [
            (k_addr, domain_map)
            for (k_kind, k_addr, k_name), domain_map in raw.items()
            if k_kind == kind and k_name == name
        ]
        if not entries:
            return None  # нет серверов этого типа — прочерк

        # Берём лучший (минимальный avg) среди рабочих
        best = None
        for _addr, domain_map in entries:
            vals = [v for v in domain_map.values() if v is not None]
            total = len(domain_map)
            ok = len(vals)
            if ok > 0:
                avg = round(sum(vals) / ok, 1)
                if best is None or avg < best[0]:
                    best = (avg, ok, total)

        if best is not None:
            return best  # (avg_ms, ok, total)

        # Серверы есть, но все провалились → TIMEOUT
        total = len(next(iter(entries))[1])
        return ("TIMEOUT", 0, total)

    # ── Формируем ячейку таблицы ──────────────────────────────────────────────
    def _cell(agg: Optional[tuple], has_server: bool) -> str:
        if not has_server or agg is None:
            return "[dim]—[/dim]"
        if agg[0] == "TIMEOUT":
            return "[red]TIMEOUT[/red]"
        avg, ok, total = agg
        ms_str = f"[green]{avg}мс[/green]"
        ratio  = f" [dim]{ok}/{total}[/dim]" if ok < total else ""
        return ms_str + ratio

    # ── Таблица ───────────────────────────────────────────────────────────────
    from rich.table import Table
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Провайдер", style="cyan", no_wrap=True, min_width=16)
    t.add_column("DoH avg",   justify="right", no_wrap=True, min_width=12)
    t.add_column("UDP avg",   justify="right", no_wrap=True, min_width=12)

    doh_ok_names = udp_ok_names = 0
    doh_total_names = len({n for _, n in doh_servers})
    udp_total_names = len({n for _, n in udp_servers})

    for name in all_names:
        has_doh = name in doh_by_name
        has_udp = name in udp_by_name
        doh_agg = _aggregate(name, "doh_wire")
        udp_agg = _aggregate(name, "udp")
        if doh_agg and doh_agg[0] != "TIMEOUT":
            doh_ok_names += 1
        if udp_agg and udp_agg[0] != "TIMEOUT":
            udp_ok_names += 1
        t.add_row(name, _cell(doh_agg, has_doh), _cell(udp_agg, has_udp))

    console.print(t)
    console.print()

    return {
        "doh_ok":    doh_ok_names,
        "doh_total": doh_total_names,
        "udp_ok":    udp_ok_names,
        "udp_total": udp_total_names,
    }