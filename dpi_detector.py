from typing import Optional, List, Dict
import asyncio
import os
import sys
import traceback
import warnings
import httpx
import signal
import argparse

warnings.filterwarnings("ignore")

try:
    from rich.panel import Panel
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: python -m pip install -r requirements.txt")
    sys.exit(1)

from utils import config
from cli.console import console
from cli.ui import ask_test_selection, print_legend
from cli.runners import run_domains_test, run_tcp_test, run_whitelist_sni_test
from core.dns_scanner import check_dns_integrity, collect_stub_ips_silently
from utils.files import load_domains, load_tcp_targets, load_whitelist_sni, get_base_dir

CURRENT_VERSION = "2.1.0"
GITHUB_REPO     = "Runnin4ik/dpi-detector"

DOMAINS         = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()
WHITELIST_SNI   = load_whitelist_sni()

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="DPI Detector — Анализатор блокировок трафика",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-t", "--tests", type=str, help="Список тестов для запуска (например: 123 или 24). Пропускает стартовое меню.")
    parser.add_argument("-p", "--proxy", type=str, help="URL прокси (напр: socks5://127.0.0.1:1080) (PROXY_URL)")
    parser.add_argument("-c", "--concurrency", type=int, help="Максимальное количество параллельных запросов (MAX_CONCURRENT)")
    parser.add_argument("-d", "--domain", type=str, action="append", help="Проверить конкретный домен(ы), игнорируя domains.txt.\nМожно указывать несколько раз: -d vk.com -d ya.ru")
    parser.add_argument("-o", "--output", type=str, help="Путь для автосохранения отчета (например: report.txt).")
    parser.add_argument("--batch", action="store_true", help="Отключает паузы и вопросы")

    return parser.parse_args()

async def _fetch_latest_version() -> Optional[str]:
    """Запрашивает последний тег с GitHub API. Возвращает строку версии или None."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    proxy_url = getattr(config, "PROXY_URL", None)
    try:
        async with httpx.AsyncClient(timeout=3.0, proxy=proxy_url, trust_env=False) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                tag = resp.json().get("tag_name", "")
                return tag.lstrip("v") if tag else None
    except Exception:
        pass
    return None


def fast_exit_handler(sig, frame):
    """Принудительный выход по первому Ctrl+C."""
    # Используем системный принт, т.к. rich может быть заблокирован
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
    """Сбрасывает накопившиеся данные в stdin чтобы буферные Enter не перезапускали тест."""
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        # Windows и другие окружения — лучшее что можно сделать без блокировки
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass


def _format_summary(
    run_dns: bool, run_domains: bool, run_tcp: bool,
    dns_intercept: int, domain_stats, tcp_stats,
    doh_unavailable=False,
) -> List[str]:
    lines = []

    if run_dns:
        total_dns = len(config.DNS_CHECK_DOMAINS)
        ok_dns = total_dns - dns_intercept
        if doh_unavailable:
            lines.append(
                f"[bold]DNS[/bold]          "
                f"[red]× DoH заблокирован провайдером[/red]"
            )
        elif dns_intercept == 0:
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
    """Сравнивает версии. Возвращает True, если на GitHub версия выше текущей."""
    try:
        def parse(v):
            return tuple(int(x) for x in v.replace('v', '').split('.') if x.isdigit())

        l_parts = parse(latest)
        c_parts = parse(current)
        return l_parts > c_parts
    except Exception:
        return False

async def main():
    args = parse_arguments()

    if args.proxy:
        config.PROXY_URL = args.proxy
    if args.concurrency:
        config.MAX_CONCURRENT = args.concurrency

    global DOMAINS
    if args.domain:
        from cli.ui import clean_hostname
        DOMAINS = [clean_hostname(d) for d in args.domain]
        config.DNS_CHECK_DOMAINS = DOMAINS

    console.clear()
    console.print(f"[bold cyan]DPI Detector v{CURRENT_VERSION}[/bold cyan]")
    console.print(f"[dim]Параллельных запросов: {config.MAX_CONCURRENT}[/dim]")

    if config.PROXY_URL:
        console.print(f"[dim]Используется прокси: [yellow]{config.PROXY_URL}[/yellow][/dim]")

    version_task = asyncio.create_task(_fetch_latest_version())
    latest_version_notified = False

    if args.tests:
        selection = args.tests
    else:
        selection = await ask_test_selection()

    run_dns     = "1" in selection
    run_domains = "2" in selection
    run_tcp     = "3" in selection
    run_wl_sni  = "4" in selection

    save_to_file = False
    result_path  = None

    if args.output:
        save_to_file = True
        result_path = args.output
    elif not args.batch:
        try:
            sys.stdout.write("\nСохранять результаты в файл? [y/N]: ")
            sys.stdout.flush()
            raw = await _readline_cancelable()
            if raw.strip().lower() in ("y", "yes", "д", "да"):
                save_to_file = True
                result_path = os.path.join(get_base_dir(), "dpi_detector_results.txt")
        except KeyboardInterrupt:
            raise

    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)
    first_run = True

    while True:
        # ── DNS ───────────────────────────────────────────────────────────────
        stub_ips: set = set()
        dns_intercept_count = 0
        doh_unavailable = False

        if run_dns and config.DNS_CHECK_ENABLED:
            stub_ips, dns_intercept_count, doh_unavailable = await check_dns_integrity()
        elif config.DNS_CHECK_ENABLED and (run_domains or run_tcp):
            try:
                stub_ips = await asyncio.wait_for(
                    collect_stub_ips_silently(),
                    timeout=config.STUB_IPS_TIMEOUT  # или вынести в config.py
                )
            except asyncio.TimeoutError:
                stub_ips = set()

        # ── Домены ────────────────────────────────────────────────────────────
        domain_stats = None
        if run_domains:
            domain_stats = await run_domains_test(semaphore, stub_ips, DOMAINS)

        # ── TCP 16-20KB ───────────────────────────────────────────────────────
        tcp_stats = None
        if run_tcp:
            tcp_stats = await run_tcp_test(semaphore, TCP_16_20_ITEMS)

        # ── Белые SNI ─────────────────────────────────────────────────────────
        if run_wl_sni:
            if WHITELIST_SNI:
                await run_whitelist_sni_test(semaphore, TCP_16_20_ITEMS, WHITELIST_SNI)
            else:
                console.print("[yellow]Файл whitelist_sni.txt пуст или не найден — тест 4 пропущен.[/yellow]")

        # ── Итоговая сводка ───────────────────────────────────────────────────
        active_tests = sum([run_dns, run_domains, run_tcp, run_wl_sni])
        console.print()
        summary_lines = _format_summary(
            run_dns, run_domains, run_tcp,
            dns_intercept_count, domain_stats, tcp_stats,
            doh_unavailable=doh_unavailable,
        )
        console.print(Panel(
            "\n".join(summary_lines),
            title="[bold]Итог[/bold]",
            border_style="cyan",
            padding=(0, 1),
            expand=False,
        ))


        if first_run:
            print_legend()
            first_run = False

        console.print("\n[bold green]Проверка завершена.[/bold green]")

        # ── Уведомление о новой версии ────────────────────────
        if not latest_version_notified:
            try:
                latest = await asyncio.wait_for(asyncio.shield(version_task), timeout=0.1)
                if latest and is_newer(latest, CURRENT_VERSION):
                    console.print(f"[bold yellow](!) Доступна новая версия: {latest}[/bold yellow]")
                    console.print(f"[dim]https://github.com/{GITHUB_REPO}/releases[/dim]")
                latest_version_notified = True
            except (asyncio.TimeoutError, Exception):
                pass

        if save_to_file and result_path:
            try:
                with open(result_path, "w", encoding="utf-8") as f:
                    f.write(console.export_text())
                console.print(f"[dim]Результаты сохранены: [cyan]{result_path}[/cyan][/dim]")
            except Exception as e:
                console.print(f"[yellow]Не удалось сохранить файл: {e}[/yellow]")

        if args.batch:
            break

        console.print(
            "\nНажмите [bold green]Enter[/bold green] чтобы повторить проверку "
            "или [bold red]Ctrl+C[/bold red] для выхода"
        )
        _flush_stdin()  # сбрасываем накопившиеся Enter чтобы не было авто-перезапуска
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