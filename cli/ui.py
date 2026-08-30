import asyncio
import os
import re
import sys
from urllib.parse import urlparse

from cli.console import console, supports_vt
from utils import config
from utils.error_classifier import clean_detail
from utils.updater import is_newer, get_launch_type


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


def _clean_status(status: str) -> str:
    """UNKNOWN-статус: убираем дублирующийся тип ошибки из ячейки."""
    if "UNKNOWN" in status:
        return re.sub(r"\s*\[dim\][^\]]+\[/dim\]", "", status).strip()
    return status


def build_domain_row(entry: dict) -> list:
    """Собирает строку таблицы доменов из entry."""
    domain = entry["domain"]
    http_status,  http_detail               = entry["http_res"]
    t12_status,   t12_detail,  t12_elapsed  = entry["t12_res"]
    t13_status,   t13_detail,  t13_elapsed  = entry["t13v4_res"]

    # UNKNOWN-статусы: тип ошибки из ячейки убираем — объяснение в Деталях
    t12_status = _clean_status(t12_status)
    t13_status = _clean_status(t13_status)
    http_status = _clean_status(http_status)

    # Проблемы по протоколам — каждая своей строкой; время — только если всё ОК
    details = []
    # HTTP REDIR (куда бы ни вёл) — не проблема, строку не пишем
    http_ok = "[green]" in http_status or "REDIR" in http_status
    t12_ok  = "[green]" in t12_status or "NO TLS1.3" in t12_status
    t13_ok  = "[green]" in t13_status or "NO TLS1.3" in t13_status

    # Проблемы по протоколам: одинаковые у 2–3 столбцов → одна строка,
    # разные → по строке с префиксом протокола
    problems = []
    if not http_ok:
        hd = clean_detail(http_detail)
        if hd:
            hd = re.sub(r"^HTTP\s+", "", hd)   # "HTTP 451" → "451" (префикс уже есть)
            problems.append(("HTTP", hd))
    if not t12_ok:
        d = clean_detail(t12_detail)
        if d:
            problems.append(("T1.2", d))
    if not t13_ok:
        d = clean_detail(t13_detail)
        if d:
            problems.append(("T1.3", d))

    # Одна колонка с ошибкой → только описание (без префикса "T1.2:"),
    # несколько колонок → префикс, чтобы было видно, где что упало
    single = len(problems) == 1
    grouped = {}
    for proto, d in problems:
        grouped.setdefault(d, []).append(proto)
    for d, protos in grouped.items():
        if single:
            details.append(d)          # одна колонка — без префикса
        elif len(protos) == 1:
            details.append(f"{protos[0]}:{d}")   # разные ошибки — видно колонку
        else:
            details.append(d)          # одинаковые ошибки — без префикса

    if http_ok and t12_ok and t13_ok:
        times = [t for t in (t12_elapsed, t13_elapsed) if t > 0]
        if times:
            details.append(f"{min(times):.1f}s")

    return [domain, http_status, t12_status, t13_status, "\n".join(details), entry["resolved_ipv4"]]


# Пресеты конкурентности в меню (↑↓ циклически) — из config.yml
CONCURRENCY_PRESETS = list(getattr(config, "CONCURRENCY_PRESETS", [1, 5, 20, 50, 100]))

_MENU_OPTIONS = [
    ("0", "Информация о сети и системе"),
    ("1", "Проверка доступности DNS-серверов"),
    ("2", "Проверка доступности доменов"),
    ("3", "Проверка TCP 16–20 KB блокировки"),
    ("4", "Поиск белых SNI для ASN"),
    ("5", "Проверка Telegram (замедление/блокировка)"),
    ("6", "Легенда статусов (справка)"),
]

_MENU_BODY = (
    "\n[bold]Какие тесты запустить?[/bold]\n"
    + "".join(f"  [cyan]{d}[/cyan]    — {label}\n" for d, label in _MENU_OPTIONS)
    + "  [cyan]123[/cyan] — [dim](по умолчанию)[/dim]"
)
# Строка подсказки меню — эталон ширины всех обводок (баннер, инфо, меню)
_MENU_HINT = (
    "  [bold white on dark_cyan] ↑↓ [/] строка │ "
    "[bold white on dark_cyan] ←→ [/] изменить │ "
    "[bold white on dark_cyan] 0-6 [/] тесты │ "
    "[bold white on dark_green] Enter [/] старт │ "
    "[bold white on dark_red] Q [/] выход"
)

# Общая ширина обводок — по ширине строки подсказки меню
from rich.cells import cell_len
from rich.text import Text
BOX_W = cell_len(Text.from_markup(_MENU_HINT).plain)


def _valid_selections() -> set:
    from itertools import combinations
    digits = "0123456"
    return {
        "".join(sorted(combo))
        for r in range(1, len(digits) + 1)
        for combo in combinations(digits, r)
    }


def _read_key_sync() -> str:
    """Одна клавиша → 'left'|'right'|'up'|'down'|'enter'|'esc'|символ."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):   # спец-клавиши: второй код — направление
            second = msvcrt.getwch()
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(second, "\x00")
        if ch == "\r":
            return "enter"
        if ch in ("\x1b", "\x03"):
            return "esc"
        return ch
    import tty
    import termios
    import select
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        # setcbreak, а не setraw: raw отключает OPOST/ONLCR — пока читается
        # клавиша, событийные перерисовки (_draw) печатают \n без \r и шапка
        # "лесенкой" разъезжается (видно на WSL). cbreak оставляет обработку
        # вывода, убирая только ICANON/ECHO.
        tty.setcbreak(fd)
        data = os.read(fd, 1)
        if not data:            # EOF (stdin закрыт) — корректный выход
            return "esc"
        # полный UTF-8 символ (многобайтовые буквы, напр. "й")
        b0 = data[0]
        if b0 & 0xE0 == 0xC0:
            need = 2
        elif b0 & 0xF0 == 0xE0:
            need = 3
        elif b0 & 0xF8 == 0xF0:
            need = 4
        else:
            need = 1
        while len(data) < need:
            more = os.read(fd, 1)
            if not more:
                break
            data += more
        ch = data.decode("utf-8", "replace")
        if ch == "\x1b":
            # Дочитываем escape-последовательность напрямую из fd: os.read
            # минует буфер TextIOWrapper (readahead не съедает хвост), окно
            # 100 мс на байт переживает раздельную доставку стрелок.
            seq = ch
            while len(seq) < 8 and seq not in ("\x1b[A", "\x1bOA", "\x1b[B",
                                                "\x1bOB", "\x1b[C", "\x1bOC",
                                                "\x1b[D", "\x1bOD"):
                r, _, _ = select.select([fd], [], [], 0.1)
                if not r:
                    break
                nxt = os.read(fd, 1)
                if not nxt:
                    break
                seq += nxt.decode("utf-8", "replace")
            if seq in ("\x1b[A", "\x1bOA"):
                return "up"
            if seq in ("\x1b[B", "\x1bOB"):
                return "down"
            if seq in ("\x1b[C", "\x1bOC"):
                return "right"
            if seq in ("\x1b[D", "\x1bOD"):
                return "left"
            return "esc"
        if ch in ("\r", "\n"):
            return "enter"
        if ch in ("\x03", "\x04"):
            return "esc"
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


async def _ask_selection_line_based(header_state: dict = None) -> str:
    """Fallback для не-терминала (пайп/CI): прежний ввод строкой.
    'u' — обновить до последней версии (если доступна)."""
    valid = _valid_selections()
    latest = (header_state or {}).get("latest") or ""
    current = (header_state or {}).get("current") or ""
    update_avail = bool(latest and current and is_newer(latest, current)
                        and get_launch_type() != "docker")
    console.print(_MENU_BODY)
    if update_avail:
        console.print(f"  [bold green]u[/bold green]    — Обновить до [bold green]v{latest}[/bold green]")
    loop = asyncio.get_running_loop()
    try:
        raw = (await loop.run_in_executor(
            None, lambda: input("\nВведите выбор [123]: ")
        )).strip()
    except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
        raise KeyboardInterrupt

    if raw == "":
        return "123"
    if raw.lower() in ("u", "у") and update_avail:
        return "u"
    if raw in valid:
        return raw

    console.print("[yellow]Неверный ввод, запускаем тесты 1, 2, 3.[/yellow]")
    return "123"


async def _ask_selection_interactive(header_state: dict = None,
                                     version_task=None) -> str:
    """
        Экран настроек (терминал): один блок — параметры и выбор тестов.
      ↑↓            — навигация по всем строкам (параметры + тесты)
      ←→            — изменить IP-версию / параллельность / чекбокс теста
      0-6           — включить/выключить тест
      Enter         — запуск выбранных тестов (или обновление, если курсор на нём)
      Q / ESC / Й   — выход (в любом состоянии)
    header_state — шапка (баннер + лениво подгружаемая версия):
      задача version_task завершается в фоне — _draw перерисовывает.
    Записывает config.IP_VERSION и config.MAX_CONCURRENT.
    Возвращает 'u' — запрошено обновление до новой версии.
"""
    from utils import config
    loop = asyncio.get_running_loop()
    valid = _valid_selections()

    def _header_render():
        """Баннер (инфо о сети — теперь тест 0, не в шапке)."""
        if not header_state:
            return None
        return header_state.get("banner")

    def _header_height() -> int:
        if not header_state:
            return 0
        return header_state.get("banner_lines", 0)

    ipv = getattr(config, "IP_VERSION", "ipv4")
    conc = config.MAX_CONCURRENT if config.MAX_CONCURRENT in CONCURRENCY_PRESETS else 50
    tests: set = set()   # по умолчанию ничего не выбрано
    cursor = 0          # активная строка (0..1)
    from utils.network import ipv6_supported
    v6_ok = ipv6_supported()   # без IPv6 в системе выбор семейства запрещён
    if not v6_ok:
        ipv = "ipv4"

    LABEL_W = 15

    def _toggle_test(d: str) -> None:
        """Включить/выключить тест d."""
        if d in tests:
            tests.discard(d)
        else:
            tests.add(d)

    def _update_row() -> tuple:
        """(доступно обновление, строка меню для него). None если нечего обновлять."""
        latest = (header_state or {}).get("latest") or ""
        current = (header_state or {}).get("current") or ""
        if not (latest and current and is_newer(latest, current)
                and get_launch_type() != "docker"):
            return False, None
        return True, (f"  {'►' if cursor == 2 else ' '} "
                      f"{'Обновить':<{LABEL_W}} до [bold green]v{latest}[/bold green]")

    menu_h = [0]   # высота области меню (панель + подсказка) — для стирания

    def _draw(first: bool = False) -> None:
        from rich.panel import Panel
        from rich import box
        if v6_ok:
            ip_opts = (
                f"{'●' if ipv == 'ipv4' else '○'} IPv4   "
                f"{'●' if ipv == 'ipv6' else '○'} IPv6"
            )
        else:
            ip_opts = "● IPv4   [dim]○ IPv6 (недоступен)[/dim]"
        conc_opts = "   ".join(
            f"{'●' if p == conc else '○'} {p}" for p in CONCURRENCY_PRESETS
        )
        up_avail, up_row = _update_row()
        param_lines = [
            "",
            f"  {'►' if cursor == 0 else ' '} {'IP-версия':<{LABEL_W}} {ip_opts}",
            f"  {'►' if cursor == 1 else ' '} {'Параллельность':<{LABEL_W}} {conc_opts}",
        ]
        if up_avail:
            param_lines.append(up_row)
        test_lines = []
        offset = 3 if up_avail else 2   # тесты начинаются после параметров
        for i, (d, label) in enumerate(_MENU_OPTIONS):
            box_mark = "\\[√]" if d in tests else "[ ]"   # \[√] — галочка (литерал, не rich-тег)
            test_lines.append(f"  {'►' if cursor == i + offset else ' '} {box_mark} {d}. {label}")
        from rich.cells import cell_len
        from rich.text import Text
        # Разделитель — между параметрами и списком тестов, по ширине контента
        sep_w = max(cell_len(Text.from_markup(l).plain)
                    for l in param_lines + test_lines) - 2
        PANEL_W = BOX_W   # общая ширина обводок — по строке подсказки меню
        lines = param_lines + ["", "  " + "─" * sep_w, ""] + test_lines + [""]
        header = _header_render()
        total = _header_height() + len(lines) + 2 + 1   # шапка + панель + подсказка
        menu_h[0] = len(lines) + 2 + 1
        if not first:
            if supports_vt():
                sys.stdout.write(f"\x1b[{total}A\r\x1b[0J")
                sys.stdout.flush()
            else:
                console.clear()
        if header:
            console.print(header)
        console.print(Panel("\n".join(lines), title="Параметры и выбор тестов", box=box.ROUNDED, padding=(0, 1), width=PANEL_W))
        console.print(_MENU_HINT)
        sys.stdout.flush()

    _draw(first=True)
    key_fut = None
    while True:
        # Ждём клавишу, но не блокируем обновление шапки (инфо о сети / версия)
        if key_fut is None or key_fut.done():
            key_fut = asyncio.ensure_future(loop.run_in_executor(None, _read_key_sync))
        waiters = {key_fut}
        if version_task is not None and not version_task.done():
            waiters.add(version_task)
        done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        if version_task is not None and version_task in done:
            try:
                version_task.result()
            except Exception:
                pass
            _draw()          # версия пришла — шапка обновилась
            continue
        try:
            key = key_fut.result()
        except (EOFError, KeyboardInterrupt, asyncio.CancelledError):
            raise KeyboardInterrupt
        key_fut = None

        up_avail, _ = _update_row()
        total_rows = (3 if up_avail else 2) + len(_MENU_OPTIONS)
        if key == "up":
            cursor = (cursor - 1) % total_rows
        elif key == "down":
            cursor = (cursor + 1) % total_rows
        elif key in ("left", "right"):
            if cursor == 0:            # IP-версия: переключение семейства
                if v6_ok:
                    ipv = "ipv6" if ipv == "ipv4" else "ipv4"
            elif cursor == 1:          # Параллельность: пресет влево/вправо
                idx = CONCURRENCY_PRESETS.index(conc)
                step = 1 if key == "right" else -1
                conc = CONCURRENCY_PRESETS[(idx + step) % len(CONCURRENCY_PRESETS)]
            elif cursor == 2 and up_avail:
                continue               # «Обновить» — стрелки не меняют
            else:                      # тест под курсором: чекбокс
                offset = 3 if up_avail else 2
                _toggle_test(_MENU_OPTIONS[cursor - offset][0])
        elif key == "enter":
            if cursor == 2 and up_avail:
                break                  # обновление — выходим с 'u'
            if not tests:
                console.print("[yellow]Выберите хотя бы один тест[/yellow]")
                continue
            break
        elif key in ("esc", "q", "й"):   # выход из программы (чистый, без traceback)
            raise SystemExit(0)
        elif key in "0123456":            # чекбоксы тестов
            _toggle_test(key)
        else:
            continue
        _draw()

    # Стираем меню с экрана: после Enter не должно оставаться «живого»
    # меню, в которое пользователь жмёт стрелки впустую (тест уже пошёл)
    try:
        if supports_vt():
            sys.stdout.write(f"\x1b[{menu_h[0]}A\r\x1b[0J")
            sys.stdout.flush()
        else:
            console.clear()
            header = _header_render()
            if header:
                console.print(header)
    except Exception:
        pass

    config.IP_VERSION = ipv
    config.MAX_CONCURRENT = conc
    if cursor == 2 and _update_row()[0]:
        return "u"
    chosen = "".join(sorted(tests))
    return chosen if chosen in valid else "123"


async def ask_test_selection(header_state: dict = None,
                             version_task=None) -> str:
    """Выбор тестов + переключалки IP-версии (←→) и конкурентности (↑↓).

    Не-терминал (пайп/CI) → прежний ввод строкой. В интерактивном режиме
    записывает config.IP_VERSION и config.MAX_CONCURRENT.
    """
    if sys.stdin is None or not sys.stdin.isatty():
        return await _ask_selection_line_based(header_state)
    return await _ask_selection_interactive(header_state, version_task)


def print_legend() -> None:
    console.print("\n[bold]Легенда статусов:[/bold]\n")

    sections = [
        ("[bold cyan]— TLS / DPI —[/bold cyan]", [
            ("TLS DPI",     "DPI обрывает или манипулирует TLS: EOF, bad record, handshake abort"),
            ("TLS MITM",    "Man-in-the-Middle: подменён сертификат (Unknown CA, Cert expired, Hostname mismatch)"),
            ("TLS BLOCK",   "Блокировка версии TLS или протокола целиком (protocol_version alert)"),
            ("TLS RST",     "Активный TCP RST на ClientHello (сброс TLS-хендшейка)"),
            ("TLS DROP",    "Таймаут TLS-хендшейка — пакеты молча отброшены (нет RST)"),
            ("UNKNOWN",     "Неизвестная ошибка (в скобках — тип исключения)"),
            ("NO TLS1.3",   "Сервер не поддерживает TLS 1.3 (норма для старых серверов)")
        ]),
        ("[bold cyan]— TCP / Соединение —[/bold cyan]", [
            ("TCP RST",     "Соединение сброшено (TCP RST пакет от DPI или сервера)"),
            ("SYN DROP",    "Таймаут TCP-соединения — SYN отправлен, ответа нет"),
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
            ("DETECTED",    "Обрыв соединения после отправки 14–36 KB"),
            ("OK",          "Все 10 запросов (до 40 КБ) прошли без обрыва"),
        ]),
        ("[bold cyan]— Прочее —[/bold cyan]", [
            ("OK",          "Сайт доступен (200–4xx без признаков блокировки)"),
            ("UNKNOWN",     "Неизвестная ошибка (в скобках — тип исключения)"),
            ("READ TIMEOUT","Сервер принял запрос, но ответ не пришёл вовремя: "
                            "DPI-обрыв/замедление, потеря пакетов или перегрузка сервера"),
            ("POOL TIMEOUT","Исчерпан пул сокетов — снизьте MAX_CONCURRENT"),
        ]),
    ]

    for section_title, items in sections:
        console.print(f"  {section_title}")
        for term, desc in items:
            console.print(f"  [dim]  [cyan]{term:<14}[/cyan] {desc}[/dim]")
        console.print()