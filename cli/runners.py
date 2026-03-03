from typing import Tuple
import re
import socket
import asyncio

import httpx
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live

import config
from cli.console import console
from cli.ui import clean_hostname, build_domain_row
from core.tls_scanner import check_domain_tls, check_http_injection, create_dpi_client
from core.tcp16_scanner import check_tcp_16_20, check_tcp_16_20_with_rtt
from utils.network import get_resolved_ip


# ── Воркеры ──────────────────────────────────────────────────────────────────

async def _resolve_worker(domain_raw: str, semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """
    Фаза 0: DNS-резолв (IPv4).
    dns_fake: False = чисто, True = заглушка, None = DNS FAIL.

    Замечание по stub_ips: stub_ips собирается через прямой UDP к публичным серверам.
    Если провайдер подменяет только системный резолвер (DoH/DoT на уровне ОС),
    а прямой UDP честный — stub_ips будет пустой и подмена здесь не обнаружится.
    Для полной картины смотри результаты DNS-теста (тест 1).
    """
    domain = clean_hostname(domain_raw)

    async with semaphore:
        resolved_ipv4 = await get_resolved_ip(domain, family=socket.AF_INET)

    entry = {
        "domain":       domain,
        "resolved_ipv4": resolved_ipv4,
        "dns_fake":     False,
        "t13v4_res":    ("[dim]—[/dim]", "", 0.0),
        "t12_res":      ("[dim]—[/dim]", "", 0.0),
        "http_res":     ("[dim]—[/dim]", ""),
    }

    if resolved_ipv4 is None:
        fail = "[yellow]DNS FAIL[/yellow]"
        entry["t13v4_res"] = (fail, "Домен не найден", 0.0)
        entry["t12_res"]   = (fail, "Домен не найден", 0.0)
        entry["http_res"]  = (fail, "Домен не найден")
        entry["dns_fake"]  = None
        return entry

    if stub_ips and resolved_ipv4 in stub_ips:
        fake = "[bold red]DNS FAKE[/bold red]"
        detail = f"DNS подмена -> {resolved_ipv4}"
        entry["t13v4_res"] = (fake, detail, 0.0)
        entry["t12_res"]   = (fake, detail, 0.0)
        entry["http_res"]  = (fake, detail)
        entry["dns_fake"]  = True

    return entry


async def _tls_worker(
    entry: dict,
    client: httpx.AsyncClient,
    tls_key: str,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза TLS: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False:
        return
    try:
        result = await check_domain_tls(entry["domain"], client, semaphore)
    except Exception:
        result = ("[dim]ERR[/dim]", "Unknown error", 0.0)
    entry[tls_key] = result


async def _http_worker(
    entry: dict,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза HTTP: пишет результат в entry in-place."""
    if entry["dns_fake"] is not False:
        return
    async with semaphore:
        try:
            result = await check_http_injection(entry["domain"], client, semaphore)
        except Exception:
            result = ("[dim]ERR[/dim]", "Unknown error")
    entry["http_res"] = result


async def _tcp16_worker(item: dict, semaphore: asyncio.Semaphore) -> list:
    ip   = item["ip"]
    port = int(item.get("port", 443))
    sni  = None if port == 80 else (item.get("sni") or config.FAT_DEFAULT_SNI)

    alive_str, status, detail = await check_tcp_16_20(ip, port, sni, semaphore)

    asn_raw = str(item.get("asn", "")).strip()
    asn_str = (
        f"AS{asn_raw}"
        if asn_raw and not asn_raw.upper().startswith("AS")
        else asn_raw.upper()
    ) or "-"

    return [item["id"], asn_str, item["provider"], alive_str, status, detail]


# ── Хелпер прогресс-бара ─────────────────────────────────────────────────────

async def _run_with_progress(tasks: list, description: str) -> list:
    results = []
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            done = len(results)
            progress.update(task_id, completed=done, description=f"{description} ({done}/{total})...")
    return results


async def _run_phase_with_progress(tasks: list, description: str) -> None:
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        completed = 0
        for future in asyncio.as_completed(tasks):
            await future
            completed += 1
            progress.update(task_id, completed=completed, description=f"{description} ({completed}/{total})...")


def _classify_domain_status(row: list, stub_ips: set) -> dict:
    """Определяет итоговый статус домена по строке таблицы (индексы 1=HTTP, 2=TLS1.2, 3=TLS1.3)."""
    block_markers = ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")

    def get_status(col_val: str) -> str:
        s = str(col_val)
        if "DNS FAKE" in s or "DNS FAIL" in s:
            return "dns_fail"
        if "OK" in s or "REDIR" in s:
            return "ok"
        if any(m in s for m in block_markers):
            return "blocked"
        if "TIMEOUT" in s:
            return "timeout"
        return "unknown"

    http_stat = get_status(row[1])
    tls12_stat = get_status(row[2])
    tls13_stat = get_status(row[3])

    if tls12_stat == "ok" or tls13_stat == "ok":
        https_stat = "ok"
    elif tls12_stat == "blocked" or tls13_stat == "blocked":
        https_stat = "blocked"
    elif tls12_stat == "timeout" or tls13_stat == "timeout":
        https_stat = "timeout"
    elif tls12_stat == "dns_fail" or tls13_stat == "dns_fail":
        https_stat = "dns_fail"
    else:
        https_stat = "unknown"

    return {
        "http": http_stat,
        "tls12": tls12_stat,
        "tls13": tls13_stat,
        "https": https_stat
    }


# ── Тест 2: домены ────────────────────────────────────────────────────────────

async def run_domains_test(semaphore: asyncio.Semaphore, stub_ips: set, domains: list) -> dict:
    """Тест 2: TLS1.3 IPv4 → TLS1.2 → HTTP injection."""
    console.print(
        f"\n[bold]Проверка доступности доменов[/bold]  "
        f"[dim]Целей: {len(domains)} | timeout: {config.TIMEOUT}s[/dim]\n"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Домен",   style="cyan", no_wrap=True, width=18)
    table.add_column("HTTP",    justify="center")
    table.add_column("TLS1.2",  justify="center")
    table.add_column("TLS1.3",  justify="center")
    table.add_column("Детали",  style="dim", no_wrap=True)

    # Фаза 0: DNS-резолв
    entries = await _run_with_progress(
        [_resolve_worker(d, semaphore, stub_ips) for d in domains],
        "Фаза 0/3: DNS-резолв..."
    )

    client_t13 = create_dpi_client("TLSv1.3")
    client_t12 = create_dpi_client("TLSv1.2")
    client_http = create_dpi_client()

    try:
        await _run_phase_with_progress(
            [_tls_worker(e, client_t13, "t13v4_res", semaphore) for e in entries],
            "Фаза 1/3: TLS 1.3..."
        )
        await _run_phase_with_progress(
            [_tls_worker(e, client_t12, "t12_res", semaphore) for e in entries],
            "Фаза 2/3: TLS 1.2..."
        )
        await _run_phase_with_progress(
            [_http_worker(e, client_http, semaphore) for e in entries],
            "Фаза 3/3: HTTP..."
        )
    finally:
        await client_t13.aclose()
        await client_t12.aclose()
        await client_http.aclose()

    rows = sorted([build_domain_row(e) for e in entries], key=lambda x: x[0])

    dns_fail_count = 0
    resolved_ips_counter: dict = {}
    for r in rows:
        resolved_ip = r[5] if len(r) > 5 else None
        if resolved_ip and stub_ips and resolved_ip in stub_ips:
            resolved_ips_counter[resolved_ip] = resolved_ips_counter.get(resolved_ip, 0) + 1
        if any("DNS FAIL" in r[col] for col in (1, 2, 3)):
            dns_fail_count += 1

    for r in rows:
        table.add_row(*r[:5])
    console.print(table)

    confirmed_stubs = {ip: c for ip, c in resolved_ips_counter.items() if stub_ips and ip in stub_ips}
    if confirmed_stubs or dns_fail_count > 0:
        console.print(f"\n[bold yellow][i] ВОЗМОЖНО НЕ НАСТРОЕН DoH:[/bold yellow]")
        if confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {c} домен(ов)" for ip, c in confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if dns_fail_count > 0:
            console.print(f"У {dns_fail_count} сайтов обнаружен DNS FAIL (Домен не найден)")
        console.print("[yellow]Рекомендация: Настройте DoH/DoT на вашем устройстве, роутере или VPN[/yellow]\n")

    block_markers = ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")

    # Build per-domain status dict for Prometheus
    per_domain: dict = {}
    for r in rows:
        domain_name = r[0]  # first column is domain name
        per_domain[domain_name] = _classify_domain_status(r, stub_ips)

    return {
        "total":      len(domains),
        "ok":         sum(1 for r in rows if "OK" in r[3] or "OK" in r[2]),
        "blocked":    sum(1 for r in rows if any(m in r[c] for c in (1,2,3) for m in block_markers)),
        "timeout":    sum(1 for r in rows if "TIMEOUT" in r[3] or "TIMEOUT" in r[2]),
        "dns_fail":   sum(1 for r in rows if "DNS FAIL" in r[3]),
        "per_domain": per_domain,
    }


# ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────────────

async def run_tcp_test(semaphore: asyncio.Semaphore, tcp_items: list) -> dict:
    """Тест 3: FAT-header TCP блокировка."""
    console.print(
        f"\n[bold]Проверка TCP 16-20KB блокировки[/bold]  "
        f"[dim]Целей: {len(tcp_items)} | timeout: {config.FAT_CONNECT_TIMEOUT}s[/dim]"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ID",        style="white")
    table.add_column("ASN",       style="yellow")
    table.add_column("Провайдер", style="cyan")
    table.add_column("Alive",     justify="center")
    table.add_column("Статус",    justify="center")
    table.add_column("Детали",    style="dim")

    tcp_results = await _run_with_progress(
        [_tcp16_worker(item, semaphore) for item in tcp_items],
        "Проверка..."
    )

    def _provider_group(provider_str: str) -> str:
        clean = re.sub(r'[^\w\s\.-]', '', provider_str).strip()
        parts = clean.split()
        return parts[0] if parts else clean

    provider_counts: dict = {}
    for row in tcp_results:
        group = _provider_group(row[2])
        provider_counts[group] = provider_counts.get(group, 0) + 1

    def _sort_key(row):
        group = _provider_group(row[2])
        try:
            id_num = int(row[0].split('-')[-1])
        except (ValueError, IndexError):
            id_num = 99999
        return (-provider_counts.get(group, 0), group, id_num)

    tcp_results.sort(key=_sort_key)

    passed  = sum(1 for r in tcp_results if "OK"       in r[4])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[4])
    mixed   = sum(1 for r in tcp_results if "MIXED"    in r[4])

    for r in tcp_results:
        table.add_row(*r[:6])
    console.print(table)

    if mixed > 0:
        console.print("[dim]Смешанные результаты указывают на балансировку DPI у провайдера[/dim]")

    return {
        "total":       len(tcp_items),
        "ok":          passed,
        "blocked":     blocked,
        "mixed":       mixed,
        "raw_results": tcp_results,
    }

# ── Тест 4: Поиск белых SNI для ASN ──────────────────────────────────────────

_SNI_BATCH_SIZE = 5


async def run_whitelist_sni_test(semaphore: asyncio.Semaphore, tcp_items: list, whitelist_sni: list) -> None:
    """Тест 4: Поиск белых SNI для ASN.

    Алгоритм:
      1. Берём все IP с портом 443.
      2. Базовая проверка — находим DETECTED IP для каждой AS.
         Если у AS несколько IP — берём DETECTED с наименьшим RTT.
      3. Для каждой DETECTED AS перебираем SNI:
         сначала пустой ("без SNI"), затем батчами из файла.
      4. Live-таблица показывает только строки подбора SNI (по одной на AS).
    """
    port443_items = [item for item in tcp_items if int(item.get("port", 443)) == 443]

    if not port443_items:
        console.print("[yellow]Нет целей с портом 443 для теста белых SNI.[/yellow]")
        return

    # Строим индекс SNI -> номер в файле (1-based)
    sni_index: dict = {}
    clean_sni_list = []
    num = 0
    for line in whitelist_sni:
        s = line.strip()
        if s and not s.startswith('#'):
            num += 1
            sni_index[s] = num
            clean_sni_list.append(s)

    from collections import defaultdict
    asn_to_items: dict = defaultdict(list)
    for item in port443_items:
        asn_raw = str(item.get("asn", "")).strip()
        asn_key = asn_raw.upper().lstrip("AS") if asn_raw else item["ip"]
        asn_to_items[asn_key].append(item)

    console.print(
        f"\n[bold]Поиск белых SNI для ASN[/bold]  "
        f"[dim]AS: {len(asn_to_items)} | IP: {len(port443_items)}"
        f" | SNI: {len(clean_sni_list)} | батч: {_SNI_BATCH_SIZE}[/dim]"
    )

    # ── Фаза 1: базовая проверка всех IP ─────────────────────────────────────
    async def _base_worker(item: dict) -> dict:
        ip      = item["ip"]
        sni     = item.get("sni") or config.FAT_DEFAULT_SNI
        asn_raw = str(item.get("asn", "")).strip()
        asn_str = (
            f"AS{asn_raw}"
            if asn_raw and not asn_raw.upper().startswith("AS")
            else asn_raw.upper()
        ) or "-"
        asn_key = asn_raw.upper().lstrip("AS") if asn_raw else ip
        alive_str, status, detail, rtt = await check_tcp_16_20_with_rtt(ip, 443, sni, semaphore)
        return {
            "item":    item,
            "id":      item.get("id", ip),
            "asn_str": asn_str,
            "asn_key": asn_key,
            "provider": item["provider"],
            "alive":   alive_str,
            "status":  status,
            "detail":  detail,
            "rtt":     rtt,
        }

    base_rows = await _run_with_progress(
        [_base_worker(item) for item in port443_items],
        "Фаза 1/2: Базовая проверка...",
    )

    # Для каждой AS выбираем DETECTED IP с наименьшим RTT
    asn_candidate: dict = {}
    for row in base_rows:
        if "DETECTED" not in row["status"]:
            continue
        ak = row["asn_key"]
        if ak not in asn_candidate:
            asn_candidate[ak] = row
        else:
            prev_rtt = asn_candidate[ak]["rtt"] or 9999
            curr_rtt = row["rtt"] or 9999
            if curr_rtt < prev_rtt:
                asn_candidate[ak] = row

    detected_rows = list(asn_candidate.values())

    if not detected_rows:
        console.print("[green]Ни одна AS не заблокирована — перебор SNI не нужен.[/green]")
        return

    console.print(
        f"[dim]Фаза 2/2: Перебор SNI для {len(detected_rows)} AS"
        f" (батч {_SNI_BATCH_SIZE}, таймаут динамический)...[/dim]"
    )

    # Ключ всех словарей = row["id"]
    sni_found: dict     = {}
    progress_info: dict = {row["id"]: "[dim]ожидание...[/dim]" for row in detected_rows}

    async def _probe_sni_batched(row: dict) -> None:
        ip     = row["item"]["ip"]
        row_id = row["id"]
        hint   = row["rtt"]

        # Шаг 0: без SNI
        progress_info[row_id] = "[dim]без SNI...[/dim]"
        try:
            _a, st0, _d = await check_tcp_16_20(ip, 443, "", semaphore, hint_rtt=hint)
            if "OK" in st0:
                sni_found[row_id] = ("(без SNI)", 0)
                progress_info[row_id] = "[bold green](без SNI)[/bold green]"
                return
        except Exception:
            pass

        batches = [
            clean_sni_list[i:i + _SNI_BATCH_SIZE]
            for i in range(0, len(clean_sni_list), _SNI_BATCH_SIZE)
        ]

        for batch in batches:
            first_num = sni_index.get(batch[0], "?")
            last_num  = sni_index.get(batch[-1], "?")
            progress_info[row_id] = f"[dim]#{first_num}–#{last_num}...[/dim]"

            async def _one(sni: str):
                a, s, d = await check_tcp_16_20(ip, 443, sni, semaphore, hint_rtt=hint)
                return sni, a, s, d

            tasks: list = [asyncio.create_task(_one(sni)) for sni in batch]
            found = False

            for fut in asyncio.as_completed(tasks):
                try:
                    sni_done, _a, st, _d = await fut
                except (asyncio.CancelledError, Exception):
                    continue
                if "OK" in st:
                    found = True
                    sni_num = sni_index.get(sni_done, 0)
                    sni_found[row_id] = (sni_done, sni_num)
                    safe = sni_done.replace(".", "\u200b.")
                    progress_info[row_id] = (
                        f"[bold green]{safe}[/bold green] [dim]#{sni_num}[/dim]"
                    )
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    break

            await asyncio.gather(*tasks, return_exceptions=True)
            if found:
                break

        if row_id not in sni_found:
            sni_found[row_id] = ("", 0)
            progress_info[row_id] = "[red]НЕ НАЙДЕН[/red]"

    # ── Live таблица — только строки подбора SNI ──────────────────────────────
    def _build_live_table() -> Table:
        t = Table(show_header=True, header_style="bold magenta", border_style="dim")
        t.add_column("ID",        style="white",  no_wrap=True)
        t.add_column("Провайдер", style="cyan",   no_wrap=True, min_width=14)
        t.add_column("ASN",       style="yellow", no_wrap=True)
        t.add_column("WL SNI",    justify="center")
        t.add_column("Детали",    min_width=36)

        for row in sorted(detected_rows, key=lambda r: r["provider"].lower()):
            rid  = row["id"]
            info = progress_info.get(rid, "…")
            if rid in sni_found and sni_found[rid][0]:
                wl = "[green]OK[/green]"
            elif rid in sni_found:
                wl = "[red]НЕТ[/red]"
            else:
                wl = "[yellow]…[/yellow]"
            t.add_row(row["id"], row["provider"], row["asn_str"], wl, info)
        return t

    with Live(_build_live_table(), console=console, refresh_per_second=4) as live:
        probe_tasks = [_probe_sni_batched(row) for row in detected_rows]
        gathered = asyncio.gather(*probe_tasks, return_exceptions=True)

        async def _refresh_loop():
            while not gathered.done():
                live.update(_build_live_table())
                await asyncio.sleep(0.25)

        refresh_task = asyncio.create_task(_refresh_loop())
        await gathered
        refresh_task.cancel()
        live.update(_build_live_table())

    found_count = sum(1 for v in sni_found.values() if v[0])
    if found_count > 0:
        console.print(
            f"[green]Найдено белых SNI: {found_count} из {len(detected_rows)} заблокированных AS[/green]"
        )
    else:
        console.print(
            f"[yellow]Белые SNI не найдены ни для одной из {len(detected_rows)} заблокированных AS[/yellow]"
        )
