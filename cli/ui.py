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

    times = []
    if "TIMEOUT" not in t12_status and t12_elapsed > 0:
        times.append(t12_elapsed)
    if "TIMEOUT" not in t13_status and t13_elapsed > 0:
        times.append(t13_elapsed)

    if times:
        details.append(f"{min(times):.1f}s")

    detail_str = " | ".join(d for d in details if d)
    return [domain, http_status, t12_status, t13_status, detail_str, entry["resolved_ipv4"]]


async def ask_test_selection() -> str:
    # Алгоритмически строим все непустые подмножества цифр 1–7
    from itertools import combinations
    digits = "1234567"
    valid = {
        "".join(sorted(combo))
        for r in range(1, len(digits) + 1)
        for combo in combinations(digits, r)
    }
    console.print(
        "\n[bold]Какие тесты запустить?[/bold]\n"
        "  [cyan]1[/cyan]    — Проверка подмены DNS\n"
        "  [cyan]2[/cyan]    — Проверка доступности DNS-серверов\n"
        "  [cyan]3[/cyan]    — Проверка доступности доменов\n"
        "  [cyan]4[/cyan]    — Проверка TCP 16-20KB блокировки\n"
        "  [cyan]5[/cyan]    — Поиск белых SNI для ASN\n"
        "  [cyan]6[/cyan]    — Проверка Telegram (замедление/блокировка)\n"
        "  [cyan]7[/cyan]    — Легенда статусов\n"
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

    console.print("[yellow]Неверный ввод, запускаем тесты 1, 2, 3.[/yellow]")
    return "123"


def print_legend() -> None:
    console.print("\n[bold]Легенда статусов:[/bold]\n")

    sections = [
        ("[bold cyan]— TLS / DPI —[/bold cyan]", [
            ("TLS DPI",     "DPI обрывает или манипулирует TLS: EOF, bad record, handshake abort"),
            ("TLS MITM",    "Man-in-the-Middle: подменён сертификат (Unknown CA, Cert expired, Hostname mismatch)"),
            ("TLS BLOCK",   "Блокировка версии TLS или протокола целиком (protocol_version alert)"),
            ("SSL ERR",     "Прочие SSL ошибки: bad key share, record layer fail, internal error"),
            ("NO TLS1.3",   "Сервер не поддерживает TLS 1.3 (норма для старых серверов)")
        ]),
        ("[bold cyan]— TCP / Соединение —[/bold cyan]", [
            ("TCP RST",     "Соединение сброшено (TCP RST пакет от DPI или сервера)"),
            ("ABORT",       "Соединение прервано (ConnectionAborted / BrokenPipe)"),
            ("REFUSED",     "TCP соединение отклонено (ECONNREFUSED)"),
            ("TIMEOUT",     "Таймаут: SYN Drop, Read timeout или OS timeout"),
            ("NET UNREACH", "Нет маршрута до сети (ICMP unreachable)"),
            ("HOST UNREACH","Нет маршрута до хоста"),
            ("OS ERR",      "Прочие OS-ошибки (errno)"),
        ]),
        ("[bold cyan]— DNS —[/bold cyan]", [
            ("DNS FAIL",    "Домен не разрешился через системный резолвер"),
            ("DNS FAKE",    "IP домена совпадает с известной заглушкой провайдера"),
            ("TIMEOUT",     "DNS-сервер не ответил в отведённое время"),
            ("BLOCKED",     "DoH-сервер заблокирован провайдером (HTTP не прошёл)"),
            ("NXDOMAIN",    "Домен не существует по мнению этого сервера"),
        ]),
        ("[bold cyan]— HTTP / Блокировки —[/bold cyan]", [
            ("BLOCKED",     "HTTP 451 — Недоступно по юридическим причинам"),
            ("ISP PAGE",    "Resolved IP является заглушкой провайдера (DNS подмена)"),
            ("REDIR",       "[green]Зелёный[/green] — редирект на тот же домен/поддомен (норма)  "
                            "[red]Красный[/red] — редирект на чужой домен (подозрительно)"),
        ]),
        ("[bold cyan]— TCP 16-20KB тест —[/bold cyan]", [
            ("DETECTED",    "Обрыв соединения после отправки 16KB+"),
            ("OK",          "Все 16 запросов прошли без обрыва"),
        ]),
        ("[bold cyan]— Прочее —[/bold cyan]", [
            ("OK",          "Сайт доступен (200–4xx без признаков блокировки)"),
            ("PROTO ERR",   "Нарушение HTTP-протокола со стороны сервера/DPI"),
            ("READ ERR",    "Ошибка чтения данных"),
            ("CONN ERR",    "Неклассифицированная ошибка подключения"),
            ("POOL TIMEOUT","Исчерпан пул сокетов — снизьте MAX_CONCURRENT"),
        ]),
    ]

    for section_title, items in sections:
        console.print(f"  {section_title}")
        for term, desc in items:
            console.print(f"  [dim]  [cyan]{term:<14}[/cyan] {desc}[/dim]")
        console.print()