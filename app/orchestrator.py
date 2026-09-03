"""Оркестрация запуска тестов и интерактивного цикла повтора."""

from typing import Optional
import asyncio
import os
import sys
import logging
from rich.panel import Panel
from rich import box

from utils import config
from cli.console import console, reset_record
from cli.ui import ask_test_selection, print_legend
from cli.input import _flush_stdin, _read_key_cancelable, _selection_flags
from cli.runners import run_domains_test, run_tcp_test, run_whitelist_sni_test, run_telegram_test
from core.dns_scanner import check_dns_availability, collect_stub_ips_silently, probe_resolver_ip
from utils.network import is_local_or_relay_ip
from utils.files import get_base_dir
from utils.system_check import get_system_dns, detect_bypass_tools
from cli.netinfo import _fetch_public_ips, _fetch_ip_info, _net_info_panel, _is_tun_name
from cli.summary import _format_summary, _export_report
from app.banner import header_render

logger = logging.getLogger(__name__)


async def fetch_network_panel() -> Optional[Panel]:
    """Сбор инфо для теста 0 («Информация о сети и системе») и построение Panel."""
    dns_info = get_system_dns()
    bypass   = detect_bypass_tools()
    try:
        ips_data = await _fetch_public_ips()
    except Exception:
        ips_data = {"v4": (None, None), "v6": (None, None)}

    v4_ip, v4_ttlb = ips_data.get("v4", (None, None))
    v6_ip, v6_ttlb = ips_data.get("v6", (None, None))

    if not v4_ip and not v6_ip:
        info = {
            "v4": {"ip": "timeout", "ttlb_ms": "timeout"},
            "v6": {"ip": "timeout", "ttlb_ms": "timeout"},
        }
        return _net_info_panel(info, dns_info, bypass)

    info = {
        "v4": {"ip": v4_ip, "ttlb_ms": v4_ttlb} if v4_ip else None,
        "v6": {"ip": v6_ip, "ttlb_ms": v6_ttlb} if v6_ip else None,
    }

    # Cymru для найденных IP (параллельно)
    v4_task = _fetch_ip_info(v4_ip) if v4_ip else None
    v6_task = _fetch_ip_info(v6_ip) if v6_ip else None

    v4_extra, v6_extra = await asyncio.gather(
        v4_task if v4_task else asyncio.sleep(0),
        v6_task if v6_task else asyncio.sleep(0)
    )

    if info.get("v4") and isinstance(v4_extra, dict):
        info["v4"].update({k: (v if v is not None else "timeout") for k, v in v4_extra.items()})
        for k in ("subnet", "org", "cc"):
            info["v4"].setdefault(k, "timeout")
    if info.get("v6") and isinstance(v6_extra, dict):
        info["v6"].update({k: (v if v is not None else "timeout") for k, v in v6_extra.items()})
        for k in ("subnet", "org", "cc"):
            info["v6"].setdefault(k, "timeout")

    # upstream роутера / VPN: опрашиваем локальные релеи
    gw = dns_info.get("gateway")
    active_ips = [ip for ip, _ in dns_info.get("active", [])]
    candidates = []
    for ip in active_ips:
        if is_local_or_relay_ip(ip) and ip not in candidates:
            candidates.append(ip)
    if gw and is_local_or_relay_ip(gw) and gw not in candidates:
        candidates.append(gw)

    up = None
    for cand in candidates:
        try:
            up = await probe_resolver_ip(cand)
            if up:
                break
        except Exception:
            pass

    if up:
        org = ""
        try:
            up_info = await _fetch_ip_info(up)
            org = up_info.get("org") or ""
        except Exception:
            pass
        a_name = dns_info.get("active_name") or ""
        label = "Upstream VPN" if _is_tun_name(a_name) else "Резолвер роутера"
        dns_info["upstream"] = up + (f" ({org})" if org else "")
        dns_info["upstream_label"] = label
    return _net_info_panel(info, dns_info, bypass)


async def execute_test_suite(
    selection: str,
    domains: list,
    tcp_items: list,
    whitelist_sni: list,
    result_path: Optional[str] = None,
) -> None:
    """Выполняет выбранные тесты, выводит сводку и экспортирует отчёт при необходимости."""
    (run_net_info, run_dns_avail, run_domains, run_tcp,
     run_wl_sni, run_telegram, run_legend, only_legend) = _selection_flags(selection)

    reset_record()
    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)

    # ── stub-заглушки для теста доменов ──
    stub_ips: set = set()
    if run_domains:
        try:
            stub_ips = await asyncio.wait_for(
                collect_stub_ips_silently(),
                timeout=config.STUB_IPS_TIMEOUT,
            )
        except (TimeoutError, asyncio.TimeoutError):
            stub_ips = set()

    # ── Тест 0: информация о сети и системе ──
    if run_net_info:
        panel = None
        try:
            if sys.stdout.isatty():
                with console.status("Получение сетевых данных...", spinner="line", spinner_style="cyan"):
                    panel = await asyncio.wait_for(fetch_network_panel(), timeout=10.0)
            else:
                panel = await asyncio.wait_for(fetch_network_panel(), timeout=10.0)
        except Exception as e:
            logger.debug("Failed to build network panel: %s", e, exc_info=True)
            panel = None
        if panel:
            console.print(panel)
        else:
            console.print("[yellow]Информация о сети недоступна.[/yellow]")
        if run_dns_avail or run_domains or run_tcp or run_wl_sni or run_telegram:
            await asyncio.sleep(2.0)

    # ── Тест 1: доступность DNS-серверов ──
    dns_avail_stats = None
    if run_dns_avail:
        dns_avail_stats = await check_dns_availability()

    # ── Тест 2: домены ──
    domain_stats = None
    if run_domains:
        domain_stats = await run_domains_test(semaphore, stub_ips, domains)

    # ── Тест 3: TCP 16-20KB ──
    tcp_stats = None
    if run_tcp:
        tcp_stats = await run_tcp_test(semaphore, tcp_items)

    # ── Тест 4: белые SNI ──
    if run_wl_sni:
        if whitelist_sni:
            await run_whitelist_sni_test(semaphore, tcp_items, whitelist_sni)
        else:
            console.print("[yellow]Файл whitelist_sni.txt пуст или не найден — тест 5 пропущен.[/yellow]")

    # ── Тест 5: Telegram ──
    telegram_stats = None
    if run_telegram:
        telegram_stats = await run_telegram_test(semaphore)

    # ── Тест 6: Легенда ──
    if run_legend and not only_legend:
        print_legend()

    # ── Итоговая сводка ──
    console.print()
    summary_table = _format_summary(
        run_dns_avail=run_dns_avail,
        run_domains=run_domains,
        run_tcp=run_tcp,
        run_telegram=run_telegram,
        domain_stats=domain_stats,
        tcp_stats=tcp_stats,
        telegram_stats=telegram_stats,
        dns_avail_stats=dns_avail_stats,
    )
    if summary_table is not None:
        console.print(Panel(
            summary_table,
            title="[bold]Итог[/bold]",
            border_style="cyan",
            padding=(0, 1),
            expand=False,
        ))

    if result_path:
        _export_report(result_path)


async def run_orchestrator_loop(
    initial_selection: str,
    header: dict,
    domains: list,
    tcp_items: list,
    whitelist_sni: list,
    result_path: Optional[str] = None,
    is_batch: bool = False,
) -> None:
    """Главный цикл: прогон тестов и интерактивное меню повтора."""
    selection = initial_selection

    while True:
        await execute_test_suite(
            selection=selection,
            domains=domains,
            tcp_items=tcp_items,
            whitelist_sni=whitelist_sni,
            result_path=result_path,
        )

        if is_batch:
            break

        console.print(Panel(
            "[bold white not dim on dark_green]  Enter  [/] Повторить   "
            "[bold white not dim on dark_blue]  M  [/] Меню   "
            "[bold white not dim on yellow]  S  [/] Экспорт   "
            "[bold white not dim on dark_red]  Q  [/] Выход",
            style="dim", box=box.HORIZONTALS,
        ))
        _flush_stdin()

        should_repeat = False
        while not should_repeat:
            try:
                key = await _read_key_cancelable()
            except KeyboardInterrupt:
                raise

            if key in ("m", "ь", "v", "м"):
                console.print()
                while True:
                    selection = await ask_test_selection(header_state=header)
                    (_, _, _, _, _, _, _, only_legend) = _selection_flags(selection)
                    if not only_legend:
                        break
                    print_legend()
                    console.print("\nНажмите [bold green]\\[Enter][/bold green] чтобы вернуться в меню...")
                    _flush_stdin()
                    try:
                        await _read_key_cancelable()
                    except KeyboardInterrupt:
                        raise
                    console.print()
                _flush_stdin()
                should_repeat = True

            elif key in ("q", "й"):
                raise SystemExit(0)

            elif key in ("s", "ы"):
                if not result_path:
                    result_path = os.path.join(get_base_dir(), "dpi_detector_results.txt")
                _export_report(result_path)
                continue

            elif key in ("enter", "\r", "\n", ""):
                should_repeat = True

            else:
                console.print("[yellow]Нажмите [Enter] для повтора, [M]/[V] для меню, [S] для экспорта, [Q] для выхода[/yellow]")

        console.print()
