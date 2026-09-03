"""DPI Detector — Анализатор блокировок сетевого трафика.

Точка входа CLI приложения.
"""

import asyncio
import signal
import sys
import traceback
import warnings

# Подавляем только DeprecationWarning сторонних библиотек, не скрывая системные ResourceWarning
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"httpx|httpcore")

from utils import config
from cli.console import console
from cli.ui import restore_terminal
from cli.input import _selection_flags
from utils.network import ipv6_supported, mask_proxy_url
from utils.files import load_domains, load_tcp_targets, load_whitelist_sni
from app import (
    CURRENT_VERSION,
    GITHUB_REPO,
    parse_arguments,
    setup_logging,
    fast_exit_handler,
    check_dependencies,
    init_header_state,
    handle_legend_menu,
    prompt_test_selection,
    run_orchestrator_loop,
    fetch_latest_version,
)

DOMAINS: list = []
TCP_16_20_ITEMS: list = []
WHITELIST_SNI: list = []

_fetch_latest_version = fetch_latest_version

__all__ = [
    "CURRENT_VERSION",
    "DOMAINS",
    "GITHUB_REPO",
    "TCP_16_20_ITEMS",
    "WHITELIST_SNI",
    "_fetch_latest_version",
    "check_dependencies",
    "fast_exit_handler",
    "main",
    "parse_arguments",
    "setup_logging",
]


async def main() -> None:
    config.load_config()
    args = parse_arguments()
    setup_logging(getattr(args, "verbose", False))

    if args.proxy:
        config.PROXY_URL = args.proxy
    if args.concurrency:
        config.MAX_CONCURRENT = args.concurrency

    global DOMAINS, TCP_16_20_ITEMS, WHITELIST_SNI
    if args.domain:
        from cli.ui import clean_hostname
        DOMAINS = [clean_hostname(d) for d in args.domain]
        config.DNS_CHECK_DOMAINS = DOMAINS
    elif not DOMAINS:
        DOMAINS = load_domains()

    if not TCP_16_20_ITEMS:
        TCP_16_20_ITEMS = load_tcp_targets()
    if not WHITELIST_SNI:
        WHITELIST_SNI = load_whitelist_sni()


    console.clear()

    if getattr(config, "CONFIG_LOAD_ERROR", None):
        console.print(f"[bold yellow]Внимание при загрузке config.yml:[/bold yellow] {config.CONFIG_LOAD_ERROR}")
    if getattr(config, "CONFIG_WARNINGS", None):
        for w in config.CONFIG_WARNINGS:
            console.print(f"[yellow]Предупреждение config.yml:[/yellow] {w}")

    header, ver_task = init_header_state()
    selection = await prompt_test_selection(header, ver_task, cli_tests=args.tests)

    console.print(
        f"[dim]Семейство IP: [cyan]{getattr(config, 'IP_VERSION', 'ipv4')}[/cyan]"
        f" | Параллельных запросов: [cyan]{config.MAX_CONCURRENT}[/cyan][/dim]"
    )
    if config.PROXY_URL:
        console.print(f"[dim]Используется прокси: [yellow]{mask_proxy_url(config.PROXY_URL)}[/yellow][/dim]")

    (_, _, _, _, _, _, _, only_legend) = _selection_flags(selection)
    if only_legend:
        selection = await handle_legend_menu(selection)

    if getattr(config, "IP_VERSION", "ipv4") == "ipv6" and not ipv6_supported():
        console.print(
            "[red]Ошибка: выбран режим IPv6, но IPv6 не настроен в системе.[/red]"
            "\n[dim]Переключите семейство на IPv4: IP_VERSION: ipv4 в config.yml"
            " или стрелки ← → в меню.[/dim]"
        )
        return

    await run_orchestrator_loop(
        initial_selection=selection,
        header=header,
        domains=DOMAINS,
        tcp_items=TCP_16_20_ITEMS,
        whitelist_sni=WHITELIST_SNI,
        result_path=args.output,
        is_batch=args.batch,
    )


if __name__ == "__main__":
    import atexit
    atexit.register(restore_terminal)
    from cli.console import install_crlf_stdout
    install_crlf_stdout()
    signal.signal(signal.SIGINT, fast_exit_handler)
    check_dependencies(GITHUB_REPO)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        fast_exit_handler(None, None)
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
        traceback.print_exc()
        if sys.platform == "win32":
            print("\nНажмите Enter для выхода...")
            input()
        restore_terminal()
        sys.exit(1)
