import os
import struct
import socket
import asyncio
from typing import Tuple, List, Union, Optional
import httpx
from utils import config
from cli.console import console


def _build_dns_query(domain: str) -> bytes:
    tx_id = os.urandom(2)
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    ancount = nscount = arcount = b'\x00\x00'
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'

    return header + qname + b'\x00\x01' + b'\x00\x01'  # QTYPE=A, QCLASS=IN


def _parse_dns_response(data: bytes, tx_id: bytes) -> Union[List[str], str]:
    if len(data) < 12:
        raise ValueError("Слишком короткий ответ")
    if data[:2] != tx_id:
        raise ValueError("ID транзакции не совпадает")

    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0x000F
    if rcode == 3:
        return "NXDOMAIN"
    if rcode != 0:
        raise ValueError(f"RCODE ошибки: {rcode}")

    qdcount, ancount, _, _ = struct.unpack(">HHHH", data[4:12])
    offset = 12

    def skip_name(pos):
        while True:
            if pos >= len(data):
                break
            if (data[pos] & 0xC0) == 0xC0:
                return pos + 2
            length = data[pos]
            if length == 0:
                return pos + 1
            pos += length + 1
        return pos

    for _ in range(qdcount):
        offset = skip_name(offset)
        offset += 4  # QTYPE + QCLASS

    ips = []
    for _ in range(ancount):
        offset = skip_name(offset)
        if offset + 10 > len(data):
            break
        atype, aclass, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if atype == 1 and aclass == 1 and rdlength == 4:
            ips.append(socket.inet_ntoa(rdata))

    return ips if ips else "EMPTY"


class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.future = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)

    def connection_lost(self, exc):
        pass


async def _resolve_udp_native(nameserver: str, domain: str, timeout: float) -> Union[List[str], str]:
    loop = asyncio.get_running_loop()
    req_data = _build_dns_query(domain)
    tx_id = req_data[:2]

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _DNSDatagramProtocol(),
        remote_addr=(nameserver, 53),
    )
    try:
        transport.sendto(req_data)
        resp_data = await asyncio.wait_for(protocol.future, timeout)
        return _parse_dns_response(resp_data, tx_id)
    finally:
        transport.close()


# ── Probe-функции ─────────────────────────────────────────────────────────────

async def _probe_udp_single(nameserver: str, domain: str) -> Optional[List[str]]:
    """Резолвит один домен через UDP. Возвращает список IP или None при ошибке."""
    try:
        res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
        return res if isinstance(res, list) else None
    except Exception:
        return None


async def _probe_doh_single(doh_url: str, domain: str) -> Optional[List[str]]:
    """Резолвит один домен через DoH. Возвращает список IP или None при ошибке."""
    headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}
    try:
        proxy_url = getattr(config, "PROXY_URL", None)
        async with httpx.AsyncClient(
            timeout=config.DNS_CHECK_TIMEOUT,
            verify=False,
            headers=headers,
            proxy=proxy_url,
            trust_env=False
        ) as client:
            resp = await client.get(doh_url, params={"name": domain, "type": "A"})
            if resp.status_code != 200:
                return None
            data = resp.json()
            if data.get("Status") == 3:
                return None
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            return ips if ips else None
    except Exception:
        return None


async def _probe_udp_all(nameserver: str, domains: list) -> dict:
    """Параллельно резолвит все домены через UDP DNS."""
    async def _query(domain):
        try:
            res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
            return domain, "OK", res
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


async def _probe_doh_all(doh_url: str, domains: list) -> dict:
    """Параллельно резолвит все домены через DoH."""
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
        timeout=config.DNS_CHECK_TIMEOUT,
        verify=False,
        headers=headers,
        proxy=proxy_url,
        trust_env=False
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


async def check_dns_integrity() -> Tuple[set, int]:
    total = len(config.DNS_CHECK_DOMAINS)
    probe_domain = config.DNS_CHECK_DOMAINS[0]

    console.print(
        f"\n[bold]Проверка подмены DNS[/bold]  "
        f"[dim]Целей: {total} | timeout: {config.DNS_CHECK_TIMEOUT}s[/dim]"
    )
    console.print("[dim]Проверяем, перехватывает ли провайдер DNS запросы...[/dim]\n")

    # ── Фаза 1: быстрый параллельный пинг всех серверов одним доменом ────────
    udp_servers  = config.DNS_UDP_SERVERS   # [(ip, name), ...]
    doh_servers  = config.DNS_DOH_SERVERS   # [(url, name), ...]

    async def _quick_udp(ip, name):
        res = await _probe_udp_single(ip, probe_domain)
        return ip, name, res  # res = List[str] или None

    async def _quick_doh(url, name):
        res = await _probe_doh_single(url, probe_domain)
        return url, name, res

    quick_udp_tasks = [_quick_udp(ip, name) for ip, name in udp_servers]
    quick_doh_tasks = [_quick_doh(url, name) for url, name in doh_servers]

    quick_results = await asyncio.gather(*quick_udp_tasks, *quick_doh_tasks)

    n_udp = len(udp_servers)
    udp_quick = quick_results[:n_udp]   # (ip, name, ips_or_None)
    doh_quick = quick_results[n_udp:]   # (url, name, ips_or_None)

    # ── Фаза 2: для тех, кто вернул None на быстром пинге — полный тест ──────
    # (параллельно для всех «сомнительных»)

    async def _full_udp_check(ip, name):
        probe = await _probe_udp_all(ip, config.DNS_CHECK_DOMAINS)
        return ip, name, probe["ok"] > 0

    async def _full_doh_check(url, name):
        probe = await _probe_doh_all(url, config.DNS_CHECK_DOMAINS)
        return url, name, probe["ok"] > 0

    needs_full_udp = [(ip, name) for ip, name, res in udp_quick if res is None]
    needs_full_doh = [(url, name) for url, name, res in doh_quick if res is None]

    full_udp_results = {}
    full_doh_results = {}

    if needs_full_udp or needs_full_doh:
        full_tasks = (
            [_full_udp_check(ip, name) for ip, name in needs_full_udp] +
            [_full_doh_check(url, name) for url, name in needs_full_doh]
        )
        full_done = await asyncio.gather(*full_tasks)
        n_full_udp = len(needs_full_udp)
        for ip, name, ok in full_done[:n_full_udp]:
            full_udp_results[(ip, name)] = ok
        for url, name, ok in full_done[n_full_udp:]:
            full_doh_results[(url, name)] = ok

    # ── Определяем финальный статус каждого сервера ───────────────────────────
    # UDP
    udp_working = []
    udp_log_lines = []
    for ip, name, quick_res in udp_quick:
        if quick_res is not None:
            udp_working.append((ip, name))
        else:
            if full_udp_results.get((ip, name), False):
                udp_working.append((ip, name))
            else:
                udp_log_lines.append(f"[dim]• UDP [yellow]{ip} ({name})[/yellow] недоступен[/dim]")

    # DoH
    doh_working = []
    doh_log_lines = []
    for url, name, quick_res in doh_quick:
        if quick_res is not None:
            doh_working.append((url, name))
        else:
            if full_doh_results.get((url, name), False):
                doh_working.append((url, name))
            else:
                doh_log_lines.append(f"[dim]• DoH [yellow]{url} ({name})[/yellow] недоступен[/dim]")

    # Выводим список только если есть проблемные серверы
    all_log = udp_log_lines + doh_log_lines
    if all_log:
        for line in all_log:
            console.print(line)
        console.print()

    # ── Выбираем по одному серверу для полного теста ──────────────────────────
    # Всегда берём первый из конфига если он рабочий, иначе первый из рабочих
    def _pick_preferred(working_list, all_list):
        if not working_list:
            return None, None
        first_key = all_list[0][0]
        for key, name in working_list:
            if key == first_key:
                return key, name
        return working_list[0]

    udp_key, udp_name_chosen = _pick_preferred(udp_working, udp_servers)
    doh_key, doh_name_chosen = _pick_preferred(doh_working, doh_servers)

    # ── Полный тест выбранными серверами ──────────────────────────────────────
    udp_probe = None
    doh_probe = None

    if udp_key:
        console.print(f"[dim]Выбран UDP: [cyan]{udp_key} ({udp_name_chosen})[/cyan] — резолвим все домены...[/dim]")
        udp_probe = await _probe_udp_all(udp_key, config.DNS_CHECK_DOMAINS)
        udp_label = f"UDP {udp_key}"
    else:
        console.print("[red]× Все UDP DNS-серверы недоступны[/red]")
        udp_probe = {"results": {d: "UNAVAIL" for d in config.DNS_CHECK_DOMAINS}}
        udp_label = "UDP DNS (недоступен)"

    if doh_key:
        console.print(f"[dim]Выбран DoH: [cyan]{doh_key} ({doh_name_chosen})[/cyan] — резолвим все домены...[/dim]")
        doh_probe = await _probe_doh_all(doh_key, config.DNS_CHECK_DOMAINS)
        doh_label = f"DoH {doh_name_chosen}"
    else:
        console.print("[red]× Все DoH-серверы недоступны[/red]")
        doh_probe = {"results": {d: "UNAVAIL" for d in config.DNS_CHECK_DOMAINS}}
        doh_label = "DoH (недоступен)"

    console.print()

    # ── Анализ результатов ────────────────────────────────────────────────────
    dns_intercept_count = doh_blocked_count = 0
    udp_ips_collection: dict = {}
    rows = []

    for domain in config.DNS_CHECK_DOMAINS:
        udp_res = udp_probe["results"].get(domain)
        doh_res = doh_probe["results"].get(domain)

        udp_ips = udp_res if isinstance(udp_res, list) else None
        doh_ips = doh_res if isinstance(doh_res, list) else None

        if udp_ips:
            udp_ips_collection[domain] = udp_ips

        udp_str = ", ".join(udp_ips[:2]) if udp_ips else str(udp_res or "—")
        doh_str = ", ".join(doh_ips[:2]) if doh_ips else str(doh_res or "—")

        if doh_res == "BLOCKED":
            doh_blocked_count += 1

        # Логика статуса: OK только если оба ответили и IP совпали
        if doh_ips and udp_ips:
            if set(doh_ips) == set(udp_ips):
                row_status = "[green]√ DNS OK[/green]"
            else:
                row_status = "[red]× DNS ПОДМЕНА[/red]"
                dns_intercept_count += 1
        elif doh_ips and not udp_ips:
            # DoH работает, UDP нет — UDP перехвачен/заблокирован
            intercept_labels = {
                "TIMEOUT":  "[red]× DNS ПЕРЕХВАТ[/red]",
                "NXDOMAIN": "[red]× FAKE NXDOMAIN[/red]",
                "EMPTY":    "[red]× FAKE EMPTY[/red]",
                "UNAVAIL":  "[yellow]× UDP недоступен[/yellow]",
            }
            row_status = intercept_labels.get(str(udp_res), "[red]× UDP БЛОК[/red]")
            if udp_res not in ("UNAVAIL",):
                dns_intercept_count += 1
        elif udp_ips and not doh_ips:
            # UDP работает, DoH нет — DoH заблокирован провайдером
            reason = "заблокирован" if doh_res == "BLOCKED" else "недоступен"
            row_status = f"[red]× DoH {reason}[/red]"
            dns_intercept_count += 1
        else:
            # Оба не ответили
            row_status = "[red]× Оба недоступны[/red]"
            dns_intercept_count += 1

        rows.append([domain, doh_str, udp_str, row_status])

    # ── Заглушки ──────────────────────────────────────────────────────────────
    ip_count: dict = {}
    for ips in udp_ips_collection.values():
        for ip in ips:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    stub_ips = {ip for ip, cnt in ip_count.items() if cnt >= 2}

    # ── Таблица ───────────────────────────────────────────────────────────────
    from rich.table import Table
    dns_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    dns_table.add_column("Домен", style="cyan")
    dns_table.add_column(doh_label, style="dim")
    dns_table.add_column(udp_label, style="dim")
    dns_table.add_column("Статус")
    for row in rows:
        dns_table.add_row(*row)
    console.print(dns_table)
    console.print()

    # ── Диагностика ───────────────────────────────────────────────────────────
    if dns_intercept_count > 0:
        console.print("[bold red][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold red]")
        console.print("Провайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY\n")
        console.print(
            "[bold yellow]ВНИМАНИЕ: Это независимая проверка и она не использует ваши настроенные DNS![/bold yellow]\n"
            "[bold yellow]Рекомендация:[/bold yellow] Настройте DoH на устройстве и роутере\n"
            "[bold green]Если DoH уже настроен — игнорируйте эту проверку.[/bold green]\n"
        )
    if doh_blocked_count > 0:
        console.print("[bold red][!] DoH заблокирован[/bold red] — провайдер блокирует зашифрованный DNS\n")

    return stub_ips, dns_intercept_count, not bool(doh_working)