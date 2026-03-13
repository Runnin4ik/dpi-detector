import asyncio
from urllib.parse import urlparse

from cli.console import console
from utils.error_classifier import clean_detail


def clean_hostname(url_or_domain: str) -> str:
    """Оставляет только домен (без протокола, пути и порта)."""
    url_or_domain = url_or_domain.strip().lower()
    if "://" not in url_or_domain:
        url_or_domain = "http://" + url_or_domain
    parsed = urlparse(url_or_domain)
    host = parsed.netloc
    if ":" in host:
        host = host.split(":")[0]
    return host


def build_domain_row(entry: dict) -> list:
    """Собирает строку таблицы доменов из entry."""
    domain = entry["domain"]
    http_status,  http_detail               = entry["http_res"]
    t12_status,   t12_detail,  t12_elapsed  = entry["t12_res"]
    t13_status,   t13_detail,  t13_elapsed  = entry["t13v4_res"]

    details = []
    d12  = clean_detail(t12_detail)
    d13  = clean_detail(t13_detail)

    all_details = {d for d in (d12, d13) if d}
    if len(all_details) == 1:
        details.append(all_details.pop())
    else:
        if d12: details.append(f"T12:{d12}")
        if d13: details.append(f"T13:{d13}")

    times = [t for t in (t12_elapsed, t13_elapsed) if t > 0]
    if times:
        details.append(f"{min(times):.1f}s")

    detail_str = " | ".join(d for d in details if d)
    return [domain, http_status, t12_status, t13_status, detail_str, entry["resolved_ipv4"]]


async def ask_test_selection() -> str:
    valid = {"1", "2", "3", "4", "12", "13", "14", "23", "24", "34",
             "123", "124", "134", "234", "1234"}
    console.print(
        "\n[bold]Какие тесты запустить?[/bold]\n"
        "  [cyan]1[/cyan]    — Проверка подмены DNS\n"
        "  [cyan]2[/cyan]    — Проверка доступности доменов\n"
        "  [cyan]3[/cyan]    — Проверка TCP 16-20KB блокировки\n"
        "  [cyan]4[/cyan]    — Поиск белых SNI для ASN\n"
        "  [cyan]123[/cyan] — [dim](по умолчанию)[/dim]"
    )
    loop = asyncio.get_running_loop()
    try:
        raw = (await loop.run_in_executor(
            None, lambda: input("\nВведите выбор [123]: ")
        )).strip()
    except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
        raise KeyboardInterrupt

    if raw == "":
        return "123"
    if raw in valid:
        return raw

    console.print("[yellow]Неверный ввод, запускаем все тесты.[/yellow]")
    return "123"


def print_legend() -> None:
    console.print("\n[bold]Легенда статусов:[/bold]")
    legend = [
        ("TLS DPI",    "DPI манипулирует или обрывает TLS соединение"),
        ("UNSUPP",     "Сервер не поддерживает TLS 1.3 (не блокировка)"),
        ("TLS MITM",   "Man-in-the-Middle: подмена/проблемы с сертификатом"),
        ("TLS BLOCK",  "Блокировка версии TLS или протокола"),
        ("SSL ERR",    "SSL/TLS ошибка (часто проблемы совместимости CDN/сервера)"),
        ("ISP PAGE",   "Запрос идёт на IP-заглушку провайдера (DNS подмена)"),
        ("BLOCKED",    "HTTP 451 (Недоступно по юридическим причинам)"),
        ("REDIR",      "[green]Зелёный[/green] = редирект на тот же домен/поддомен  [red]Красный[/red] = редирект на чужой домен"),
        ("TIMEOUT",    "Таймаут соединения или чтения"),
        ("DNS FAIL",   "Не удалось разрешить доменное имя"),
        ("OK",         "Сайт доступен"),
    ]
    for term, desc in legend:
        console.print(f"[dim]• [cyan]{term:<12}[/cyan] = {desc}[/dim]")