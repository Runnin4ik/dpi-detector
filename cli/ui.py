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
    t13v4_status, t13v4_detail, t13v4_elapsed = entry["t13v4_res"]
    t13v6_status, t13v6_detail, t13v6_elapsed = entry["t13v6_res"]

    details = []
    d12   = clean_detail(t12_detail)
    d13v4 = clean_detail(t13v4_detail)
    d13v6 = clean_detail(t13v6_detail)

    all_details = {d for d in (d12, d13v4, d13v6) if d}
    if len(all_details) == 1:
        details.append(all_details.pop())
    else:
        if d12:   details.append(f"T12:{d12}")
        if d13v4: details.append(f"T13v4:{d13v4}")
        if d13v6: details.append(f"T13v6:{d13v6}")

    times = [t for t in (t12_elapsed, t13v4_elapsed, t13v6_elapsed) if t > 0]
    if times:
        details.append(f"{min(times):.1f}s")

    detail_str = " | ".join(d for d in details if d)
    return [domain, http_status, t12_status, t13v4_status, t13v6_status, detail_str, entry["resolved_ipv4"]]


async def ask_test_selection() -> str:
    valid = {"1", "2", "3", "12", "13", "23", "123"}
    console.print(
        "\n[bold]Какие тесты запустить?[/bold]\n"
        "  [cyan]1[/cyan]   — DNS целостность\n"
        "  [cyan]2[/cyan]   — Проверка доменов (TLS + HTTP injection)\n"
        "  [cyan]3[/cyan]   — TCP 16-20KB блокировка\n"
        "  [cyan]123[/cyan] — Все тесты [dim](по умолчанию)[/dim]"
    )
    loop = asyncio.get_running_loop()
    try:
        raw = (await loop.run_in_executor(
            None, lambda: input("\nВведите выбор [123]: ")
        )).strip()
    except (EOFError, KeyboardInterrupt):
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
        ("ISP PAGE",   "Редирект на страницу провайдера или блок-страница"),
        ("BLOCKED",    "HTTP 451 (Недоступно по юридическим причинам)"),
        ("TIMEOUT",    "Таймаут соединения или чтения"),
        ("DNS FAIL",   "Не удалось разрешить доменное имя"),
        ("OK / REDIR", "Сайт доступен (может быть редирект)"),
    ]
    for term, desc in legend:
        console.print(f"[dim]• [cyan]{term:<12}[/cyan] = {desc}[/dim]")