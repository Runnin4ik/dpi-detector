from typing import Optional, List, Dict
import asyncio
import os
import sys
import traceback
import warnings
import httpx
import signal

warnings.filterwarnings("ignore")

try:
    from rich.panel import Panel
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: python -m pip install -r requirements.txt")
    sys.exit(1)

import config
from cli.console import console
from cli.ui import ask_test_selection, print_legend
from cli.runners import run_domains_test, run_tcp_test, run_whitelist_sni_test
from core.dns_scanner import check_dns_integrity, collect_stub_ips_silently
from utils.files import load_domains, load_tcp_targets, load_whitelist_sni, get_base_dir
from metrics.prometheus import (
    start_metrics_server,
    record_dns,
    record_domains,
    record_domain_statuses,
    record_tcp,
    record_tcp_target_statuses,
    record_run_timestamp,
)

CURRENT_VERSION = "2.0.1"
GITHUB_REPO     = "Runnin4ik/dpi-detector"

DOMAINS         = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()
WHITELIST_SNI   = load_whitelist_sni()

# ---------------------------------------------------------------------------
# Режим запуска:
#   DOCKER_MODE=1   — старый флаг, по-прежнему работает (treated as schedule)
#   RUN_MODE=once   — запустить тесты один раз и выйти
#   RUN_MODE=schedule — запускать периодически (по умолчанию в DOCKER_MODE)
#   TESTS=123       — набор тестов для неинтерактивного режима (по умолчанию "123")
#   CHECK_INTERVAL  — интервал в секундах для schedule-режима (по умолчанию 7200)
# ---------------------------------------------------------------------------
_DOCKER_MODE = os.environ.get("DOCKER_MODE", "0").lower() in ("1", "true", "yes")
_RUN_MODE    = os.environ.get("RUN_MODE", "").strip().lower()  # once | schedule | ""

# Нормализуем: если задан старый DOCKER_MODE и RUN_MODE не указан явно
if _DOCKER_MODE and not _RUN_MODE:
    _RUN_MODE = "schedule"

_NON_INTERACTIVE = _RUN_MODE in ("once", "schedule")  # без интерактивного UI

if _NON_INTERACTIVE:
    start_metrics_server()


async def _fetch_latest_version() -> Optional[str]:
    """Запрашивает последний тег с GitHub API."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                tag = resp.json().get("tag_name", "")
                return tag.lstrip("v") if tag else None
    except Exception:
        pass
    return None


def fast_exit_handler(sig, frame):
    sys.stdout.write("\n\033[91m\033[1mПрервано пользователем.\033[0m\n")
    sys.stdout.flush()
    os._exit(0)

async def _readline_cancelable() -> str:
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(None, sys.stdin.readline)
        result = await future
        return result.rstrip("\n")
    except asyncio.CancelledError:
        raise KeyboardInterrupt

def _flush_stdin() -> None:
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass


def _format_summary(
    run_dns: bool, run_domains: bool, run_tcp: bool,
    dns_intercept: int, domain_stats: Optional[Dict], tcp_stats: Optional[Dict]
) -> List[str]:
    lines = []

    if run_dns:
        total_dns = len(config.DNS_CHECK_DOMAINS)
        ok_dns = total_dns - dns_intercept
        if dns_intercept == 0:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[green]√ {ok_dns}/{total_dns} не подменяется[/green]"
            )
        elif dns_intercept == total_dns:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[red]× {dns_intercept}/{total_dns} подменяется провайдером[/red]"
            )
        else:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[green]√ {ok_dns}/{total_dns} OK[/green]"
                f"  [red]× {dns_intercept}/{total_dns} подменяется провайдером[/red]"
            )

    if domain_stats:
        d = domain_stats
        pct = int(d["ok"] / d["total"] * 100) if d["total"] else 0
        line = (
            f"[bold]Домены[/bold]       "
            f"[green]√ {d['ok']}/{d['total']} OK[/green]"
            + (f"  [red]× {d['blocked']} блок.[/red]" if d['blocked'] else "")
            + (f"  [yellow]⏱ {d['timeout']} таймаут[/yellow]" if d['timeout'] else "")
            + f"  [dim]({pct}% ОК)[/dim]"
        )
        lines.append(line)

    if tcp_stats:
        t = tcp_stats
        pct = int(t["ok"] / t["total"] * 100) if t["total"] else 0
        line = (
            f"[bold]TCP 16-20KB[/bold]  "
            f"[green]√ {t['ok']}/{t['total']} OK[/green]"
            + (f"  [red]× {t['blocked']} блок.[/red]" if t['blocked'] else "")
            + (f"  [yellow]≈ {t['mixed']} смеш.[/yellow]" if t['mixed'] else "")
            + f"  [dim]({pct}% ОК)[/dim]"
        )
        lines.append(line)

    return lines


def is_newer(latest: str, current: str) -> bool:
    try:
        def parse(v):
            return tuple(int(x) for x in v.replace('v', '').split('.') if x.isdigit())
        return parse(latest) > parse(current)
    except Exception:
        return False


def _resolve_selection_from_env() -> str:
    """Читает переменную TESTS и возвращает строку выбора (напр. '123')."""
    raw = os.environ.get("TESTS", "123").strip()
    # Валидируем: принимаем только символы 1-4
    selection = "".join(c for c in raw if c in "1234")
    return selection or "123"


async def _ask_run_mode_interactive() -> str:
    """Интерактивно спрашивает режим запуска. Возвращает 'once' или 'schedule'."""
    console.print()
    console.print("[bold]Режим запуска:[/bold]")
    console.print("  [bold cyan]1[/bold cyan] — Одиночная проверка (запустить и выйти)")
    console.print("  [bold cyan]2[/bold cyan] — Фоновый режим (повторять по расписанию)")
    sys.stdout.write("\nВведите выбор [1]: ")
    sys.stdout.flush()
    try:
        raw = await _readline_cancelable()
        raw = raw.strip()
    except KeyboardInterrupt:
        raise
    return "schedule" if raw == "2" else "once"


def _build_domain_statuses(domain_stats: Dict, domains: list) -> list:
    """Build per-domain status list for Prometheus metrics.

    Uses domain_stats keys: per_domain (if present) or falls back to aggregate
    status inference. Expected domain_stats to contain 'per_domain' dict:
      {domain: status_dict}
    """
    per = domain_stats.get("per_domain")
    if per:
        return list(per.items())
    # Fallback: mark all domains with unknown status (shouldn't happen if runners updated)
    return [(d, {"https": "unknown", "tls12": "unknown", "tls13": "unknown", "http": "unknown"}) for d in domains]


def _build_tcp_target_statuses(tcp_results_raw: list) -> list:
    """Convert raw tcp results rows to list of dicts for Prometheus.

    Each row: [id, asn_str, provider, alive_str, status_str, detail]
    status_str contains 'OK', 'DETECTED', 'MIXED' substrings.
    """
    out = []
    for row in tcp_results_raw:
        tid, asn_str, provider = row[0], row[1], row[2]
        status_str = row[4] if len(row) > 4 else ""
        if "OK" in status_str:
            status = "ok"
        elif "DETECTED" in status_str:
            status = "blocked"
        elif "MIXED" in status_str:
            status = "mixed"
        else:
            status = "unknown"
        out.append({"id": tid, "provider": provider, "asn": asn_str, "status": status})
    return out


async def run_tests(selection: str, semaphore: asyncio.Semaphore):
    """Выполняет набор тестов по строке выбора, обновляет метрики."""
    run_dns     = "1" in selection
    run_domains = "2" in selection
    run_tcp     = "3" in selection
    run_wl_sni  = "4" in selection

    stub_ips: set = set()
    dns_intercept_count = 0

    if run_dns and config.DNS_CHECK_ENABLED:
        stub_ips, dns_intercept_count = await check_dns_integrity()
    elif config.DNS_CHECK_ENABLED and (run_domains or run_tcp):
        stub_ips = await collect_stub_ips_silently()

    if run_dns and config.DNS_CHECK_ENABLED:
        total_dns = len(config.DNS_CHECK_DOMAINS)
        record_dns(
            total=total_dns,
            intercepted=dns_intercept_count,
            ok=total_dns - dns_intercept_count,
        )

    domain_stats = None
    if run_domains:
        domain_stats = await run_domains_test(semaphore, stub_ips, DOMAINS)
        record_domains(
            total=domain_stats["total"],
            ok=domain_stats["ok"],
            blocked=domain_stats["blocked"],
            timeout=domain_stats["timeout"],
            dns_fail=domain_stats["dns_fail"],
        )
        # Per-domain labeled metrics
        domain_statuses = _build_domain_statuses(domain_stats, DOMAINS)
        record_domain_statuses(domain_statuses)

    tcp_stats = None
    if run_tcp:
        tcp_stats = await run_tcp_test(semaphore, TCP_16_20_ITEMS)
        record_tcp(
            total=tcp_stats["total"],
            ok=tcp_stats["ok"],
            blocked=tcp_stats["blocked"],
            mixed=tcp_stats["mixed"],
        )
        # Per-TCP-target labeled metrics
        tcp_target_statuses = _build_tcp_target_statuses(tcp_stats.get("raw_results", []))
        record_tcp_target_statuses(tcp_target_statuses)

    if run_wl_sni:
        if WHITELIST_SNI:
            await run_whitelist_sni_test(semaphore, TCP_16_20_ITEMS, WHITELIST_SNI)
        else:
            console.print("[yellow]Файл whitelist_sni.txt пуст или не найден — тест 4 пропущен.[/yellow]")

    record_run_timestamp()

    active_tests = sum([run_dns, run_domains, run_tcp, run_wl_sni])
    if active_tests >= 2:
        console.print()
        summary_lines = _format_summary(
            run_dns, run_domains, run_tcp,
            dns_intercept_count, domain_stats, tcp_stats,
        )
        console.print(Panel(
            "\n".join(summary_lines),
            title="[bold]Итог[/bold]",
            border_style="cyan",
            padding=(0, 1),
            expand=False,
        ))

    console.print("\n[bold green]Проверка завершена.[/bold green]")


async def main():
    console.clear()
    console.print(f"[bold cyan]DPI Detector v{CURRENT_VERSION}[/bold cyan]")
    console.print(f"[dim]Параллельных запросов: {config.MAX_CONCURRENT}[/dim]")

    version_task = asyncio.create_task(_fetch_latest_version())
    latest_version_notified = False

    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)

    # ── Определяем effective_mode и selection ─────────────────────────────────────────────
    if _NON_INTERACTIVE:
        # Режим задан через переменные окружения
        effective_mode = _RUN_MODE  # once | schedule
        selection = _resolve_selection_from_env()
        console.print(f"[dim]Режим: [bold]{effective_mode}[/bold]  Тесты: {selection}[/dim]")
        if effective_mode == "schedule":
            interval = int(os.environ.get("CHECK_INTERVAL", "7200"))
            console.print(f"[dim]Интервал: {interval}s[/dim]")
    else:
        # Интерактивный режим: сначала выбор тестов, потом режим запуска
        selection = await ask_test_selection()
        effective_mode = await _ask_run_mode_interactive()
        if effective_mode == "schedule":
            sys.stdout.write("Интервал в секундах [7200]: ")
            sys.stdout.flush()
            try:
                raw_interval = (await _readline_cancelable()).strip()
            except KeyboardInterrupt:
                raise
            interval = int(raw_interval) if raw_interval.isdigit() else 7200
        save_to_file = False
        result_path  = None
        if effective_mode == "once":
            sys.stdout.write("\nСохранять результаты в файл? [y/N]: ")
            sys.stdout.flush()
            try:
                raw = (await _readline_cancelable()).strip().lower()
            except KeyboardInterrupt:
                raise
            if raw in ("y", "yes", "д", "да"):
                save_to_file = True
                result_path = os.path.join(get_base_dir(), "dpi_detector_results.txt")

    # ── Основной цикл ──────────────────────────────────────────────────────────────────
    first_run = True
    while True:
        await run_tests(selection, semaphore)

        if first_run:
            if not _NON_INTERACTIVE:
                print_legend()
            first_run = False

        # Уведомление о новой версии
        if not latest_version_notified:
            try:
                latest = await asyncio.wait_for(asyncio.shield(version_task), timeout=0.1)
                if latest and is_newer(latest, CURRENT_VERSION):
                    console.print(f"[bold yellow](!) Доступна новая версия: {latest}[/bold yellow]")
                    console.print(f"[dim]https://github.com/{GITHUB_REPO}/releases[/dim]")
                latest_version_notified = True
            except (asyncio.TimeoutError, Exception):
                pass

        # ── once: сохранить при необходимости и выйти ─────────────────────────────
        if effective_mode == "once":
            if not _NON_INTERACTIVE and save_to_file and result_path:
                try:
                    with open(result_path, "w", encoding="utf-8") as f:
                        f.write(console.export_text())
                    console.print(f"[dim]Результаты сохранены: [cyan]{result_path}[/cyan][/dim]")
                except Exception as e:
                    console.print(f"[yellow]Не удалось сохранить файл: {e}[/yellow]")
            break  # выходим после первого прогона

        # ── schedule: ждём интервал, затем повторяем ──────────────────────────────
        if effective_mode == "schedule":
            if _NON_INTERACTIVE:
                interval = int(os.environ.get("CHECK_INTERVAL", "7200"))
            console.print(f"[dim]Следующий прогон через {interval}s...[/dim]")
            await asyncio.sleep(interval)
            console.print()
            continue

        # ── интерактивный once или неизвестный режим: предложить повторить ────────
        console.print(
            "\nНажмите [bold green]Enter[/bold green] чтобы повторить проверку "
            "или [bold red]Ctrl+C[/bold red] для выхода"
        )
        _flush_stdin()
        try:
            await _readline_cancelable()
        except KeyboardInterrupt:
            raise
        console.print()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, fast_exit_handler)

    try:
        asyncio.run(main())
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
        traceback.print_exc()
        if sys.platform == 'win32':
            print("\nНажмите Enter для выхода...")
            input()
        os._exit(1)
