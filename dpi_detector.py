from typing import Optional, List, Dict
from core.telegram_scanner import _fmt_speed as _tg_fmt, _fmt_size as _tg_size
import asyncio
import os
import re
import sys
import time
import traceback
import warnings
import httpx
import signal
import argparse

warnings.filterwarnings("ignore")

try:
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: python -m pip install -r requirements.txt")
    sys.exit(1)

from utils import config
from cli.console import console, reset_record
from cli.ui import ask_test_selection, print_legend, BOX_W
from cli.runners import run_domains_test, run_tcp_test, run_whitelist_sni_test, run_telegram_test
from core.dns_scanner import (
    check_dns_availability,
    collect_stub_ips_silently,
    probe_resolver_ip,
)
from utils.network import ipv6_supported
from utils.files import load_domains, load_tcp_targets, load_whitelist_sni, get_base_dir
from utils.system_check import get_system_dns, detect_bypass_tools

CURRENT_VERSION = "4.0.0"
GITHUB_REPO     = "Runnin4ik/dpi-detector"

# DoH-эндпоинты для запросов Team Cymru (dns.google первым — работает и без SNI)
_CYMRU_DOH_URLS = tuple(getattr(config, "CYMRU_DOH_SERVERS",
                                ("https://dns.google/resolve",
                                 "https://cloudflare-dns.com/dns-query")))


def _flag_emoji(cc: str) -> str:
    """Двухбуквенный код страны → эмодзи-флаг (🇷🇺). Пусто при невалидном коде."""
    if len(cc) == 2 and cc.isalpha():
        return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in cc)
    return ""


async def _fetch_public_ip(timeout: float = 5.0) -> tuple:
    """Внешний IPv4 + TTLB (мс). Ошибка → поднимает исключение."""
    t0 = time.perf_counter()
    proxy_url = getattr(config, "PROXY_URL", None)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 trust_env=False, proxy=proxy_url) as client:
        ip = None
        for url in getattr(config, "IP_LOOKUP_URLS",
                           ("https://api.ipify.org", "https://icanhazip.com",
                            "https://ifconfig.me/ip")):
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    cand = resp.text.strip()
                    if cand.count(".") == 3 and all(p.isdigit() for p in cand.split(".")):
                        ip = cand
                        break
            except Exception:
                continue
    if not ip:
        raise RuntimeError("внешний IP не определён")
    return ip, int((time.perf_counter() - t0) * 1000)


async def _fetch_ip_info(ip: str, timeout: float = 5.0) -> dict:
    """Team Cymru через DoH: {asn, subnet, cc, org}. Ошибка → {}."""
    from utils.network import pin_host
    info = {}
    proxy_url = getattr(config, "PROXY_URL", None)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 trust_env=False, proxy=proxy_url) as client:
        rev = ".".join(reversed(ip.split(".")))
        for url, ehost in [await pin_host(u) for u in _CYMRU_DOH_URLS]:
            try:
                resp = await client.get(
                    url, params={"name": f"{rev}.origin.asn.cymru.com", "type": "TXT"},
                    headers={"Host": ehost} if ehost else None,
                    extensions={"sni_hostname": ehost} if ehost else None,
                )
                answers = resp.json().get("Answer", []) if resp.status_code == 200 else []
                if answers:
                    fields = [p.strip() for p in answers[0]["data"].strip('"').split("|")]
                    # ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
                    # Префикс может отсутствовать — ищем поля по типу, а не позиции;
                    # несколько ASN приходят через пробел — берём первый (основной)
                    info["asn"] = fields[0].split()[0]
                    for f in fields[1:]:
                        if "/" in f and f[0].isdigit():
                            info["subnet"] = f
                        elif re.fullmatch(r"[A-Z]{2}", f):
                            info["cc"] = f
                    info["org"] = re.sub(r"\s+", " ", fields[-1]).strip() if fields[-1] else ""
                    break
            except Exception:
                continue

        # Если в origin-ответе нет имени AS (последнее поле — дата выделения), берём из AS{asn}.asn.cymru.com
        if info.get("asn") and re.fullmatch(r"\d{4}-\d{2}-\d{2}", info.get("org", "") or ""):
            for url, ehost in [await pin_host(u) for u in _CYMRU_DOH_URLS]:
                try:
                    resp = await client.get(
                        url, params={"name": f"AS{info['asn']}.asn.cymru.com", "type": "TXT"},
                        headers={"Host": ehost} if ehost else None,
                        extensions={"sni_hostname": ehost} if ehost else None,
                    )
                    answers = resp.json().get("Answer", []) if resp.status_code == 200 else []
                    if answers:
                        fields = [p.strip() for p in answers[0]["data"].strip('"').split("|")]
                        if len(fields) >= 2:
                            info["org"] = re.sub(r"\s+", " ", fields[-1]).strip() or info.get("org", "")
                        break
                except Exception:
                    continue
    # Дата выделения вместо имени AS (имя так и не пришло) — не показываем
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", info.get("org", "") or ""):
        info["org"] = ""
    return info


def _dns_block_lines(label: str, ips: list, tail: str) -> list:
    """Строки DNS-блока (rich-разметка): label + IP + tail, перенос по 70 колонкам.
    Хвост приклеивается к последнему чанку, если влезает; иначе — своей строкой."""
    w, ind = 70, 15
    joined = ", ".join(ips)
    if len(label) + len(joined) + len(tail) <= w:
        return [f"{label}[cyan]{joined}[/cyan]{tail}"]
    limit_end = w - ind - len(tail)
    tail_own = limit_end < 8
    if tail_own:
        limit_end = w - ind
    end_chunk, rest = "", list(ips)
    while rest:
        ip = rest.pop()
        piece = ip if not end_chunk else ip + ", " + end_chunk
        if len(piece) <= limit_end:
            end_chunk = piece
        else:
            rest.append(ip)
            break
    chunks, cur = [], ""
    for ip in rest:
        piece = ip if not cur else cur + ", " + ip
        if len(piece) <= w - ind:
            cur = piece
        else:
            chunks.append(cur)
            cur = ip
    if cur:
        chunks.append(cur)
    if end_chunk:
        chunks.append(end_chunk)
    out = []
    for i, c in enumerate(chunks):
        if i == len(chunks) - 1 and not tail_own:
            out.append(f"{' ' * ind}[cyan]{c}[/cyan]{tail}")
        else:
            out.append(f"{' ' * ind}[cyan]{c}[/cyan]")
    out[0] = f"{label}[cyan]{chunks[0]}[/cyan]"
    if tail_own:
        out.append(f"{' ' * ind}{tail}")
    return out


def _is_tun_name(name: str) -> bool:
    """TUN-адаптер VPN (xray/sing-box/WireGuard/WARP): happ-tun, happ-default-tun,
    happ-xray, utun, wintun, WARPv1_* и т.п."""
    n = (name or "").lower()
    return ("tun" in n or "xray" in n or "sing-box" in n or "singbox" in n
            or "wireguard" in n or "warp" in n or "tailscale" in n
            or "zerotier" in n or "mullvad" in n)


def _net_info_lines(net_info: dict, sys_dns: dict, bypass: list) -> list:
    """Строки блока "Информация о сети и системе" (с rich-разметкой)."""
    lines = []
    ip   = net_info.get("ip") or "…"
    sub  = net_info.get("subnet") or "…"
    ttlb = net_info.get("ttlb_ms")
    if ttlb is None:
        ttlb_s = "…"
    elif ttlb == "timeout":
        ttlb_s = "[red]timeout[/red]"
    elif isinstance(ttlb, int):
        ttlb_s = f"[dim]{ttlb} ms[/dim]"
    else:
        ttlb_s = str(ttlb)

    def _v(v: str) -> str:
        return f"[red]{v}[/red]" if v == "timeout" else f"[cyan]{v}[/cyan]"

    lines.append(f"IP: {_v(ip)}  Subnet: {_v(sub)}  TTLB: {ttlb_s}")
    org = net_info.get("org") or "…"
    asn = net_info.get("asn") or ""
    org_s = f"{org} (AS{asn})" if asn else org
    lines.append(f"Org: {_v(org_s)}")
    cc = net_info.get("cc") or "…"
    loc = f"{_flag_emoji(cc)} {cc}".strip()
    lines.append(f"Location: {_v(loc)}")
    os_line = (sys_dns or {}).get("os")
    if os_line:
        lines.append(f"ОС: {_v(os_line)}")

    active = (sys_dns or {}).get("active")
    if active:
        a_name = (sys_dns or {}).get("active_name")
        a_ip   = (sys_dns or {}).get("active_ip")
        iface_shown = bool(a_name and a_ip)   # «Активный интерфейс» — ниже
        doh    = (sys_dns or {}).get("doh", {})
        mark   = lambda ips: [ip + "(DoH)" if ip in doh else ip for ip in ips]

        # Системный DNS: метка источника (DHCP/вручную/прокси WSL);
        # имя адаптера — только если «Активный интерфейс» не выведен
        from utils.network import get_fake_ip_type
        ips_all = [ip for ip, _ in active]
        # Метка источника: DHCP (раздал роутер), прокси WSL и fake-ip (xray
        # слушает виртуальный адрес 198.18.0.0/15) информативны;
        # «вручную» для static ничего не добавляет — не показываем
        srcs = {src for _, src in active}
        src_label = ""
        if any(get_fake_ip_type(ip) == "fakeip" for ip in ips_all):
            src_label = "fake-ip"
        elif _is_tun_name(a_name):
            src_label = "TUN"        # TUN-адаптер (xray/sing-box) с обычной подсетью
        elif srcs == {"wsl"}:
            src_label = "прокси WSL"
        elif srcs == {"dhcp"}:
            src_label = "DHCP"
        if src_label in ("fake-ip", "TUN") and any("xray" in b.lower() for b in bypass):
            src_label += ", xray"
        if src_label and not iface_shown and a_name:
            tail = f" ({src_label}, {a_name})"
        elif src_label:
            tail = f" ({src_label})"
        elif not iface_shown and a_name:
            tail = f" ({a_name})"
        else:
            tail = ""
        lines.extend(_dns_block_lines("Системный DNS: ", mark(ips_all), tail))

        # Активный интерфейс — под системным DNS, перед неактивными
        if iface_shown:
            lines.append(f"Активный интерфейс: {_v(a_ip)} ({a_name})")

        other = (sys_dns or {}).get("other_static", [])
        if other:
            by_name, order = {}, []
            for ip, n in other:
                if n not in by_name:
                    by_name[n], order = [], order + [n]
                by_name[n].append(ip)
            for k, n in enumerate(order):
                label = f"{'Неактивные DNS:':<16}" if k == 0 else " " * 16
                lines.extend(_dns_block_lines(label, mark(by_name[n]), f" ({n})"))
    up = (sys_dns or {}).get("upstream")
    if up:
        up_label = (sys_dns or {}).get("upstream_label") or "Резолвер роутера"
        lines.append(f"{up_label}: {_v(up)}")
    # VPN-клиенты показываем только когда туннель активен: процесс может быть
    # запущен, но выключенный VPN не обходит DPI. Признак активности AmneziaVPN:
    # её адаптер жив и имеет DNS (умная маршрутизация держит default-маршрут
    # на LAN, но туннель поднят и виден по DNS адаптера)
    if bypass:
        a_names = [((sys_dns or {}).get("active_name") or "").lower()]
        a_names += [n.lower() for _, n in (sys_dns or {}).get("other_static", [])]
        names_l = " ".join(a_names)
        bypass = [t for t in bypass
                  if t != "AmneziaWG" or ("warp" in names_l or "amnezia" in names_l)]
    wsl_net = (sys_dns or {}).get("wsl_net")
    if wsl_net:
        lines.append(f"WSL-сеть: {_v(wsl_net)}")
    if bypass:
        lines.append(f"Локальный обход DPI на устройстве: [yellow]{', '.join(bypass)}[/yellow]")
    else:
        lines.append("Локальный обход DPI на устройстве: [dim]не обнаружен[/dim]")
    return lines


def _render_net_info_block(net_info: dict, sys_dns: dict, bypass: list) -> tuple:
    """Отрендеренная панель инфо о сети: (plain-текст, высота). Пусто → ("", 0)."""
    lines = _net_info_lines(net_info, sys_dns, bypass)
    if not lines:
        return "", 0
    from rich.cells import cell_len
    from rich.text import Text
    # Общая ширина обводок (BOX_W — по подсказке меню); если контент шире — по нему
    width = max(BOX_W, max(cell_len(Text.from_markup("  " + l).plain) for l in lines) + 6)
    with console.capture() as cap:
        console.print(Panel(
            "\n".join("  " + l for l in lines),
            title="Информация о сети и системе",
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 1),
            width=width,
        ))
    text = cap.get()
    return text, len(text.splitlines())


def _render_banner(badge: str = "Проверка обновлений...") -> tuple:
    """Баннер (ширина по контенту + запас): заголовок в верхней рамке;
    две строки по два поля — автор/GitHub и чат/статус обновлений (4-й
    элемент). Цвета: рамка/заголовок — cyan, подписи — серые, "Runni" —
    пастельный фиолетовый, разделители — cyan, бейдж "актуально" — мягкий
    зелёный (в пайпе цвета отключаются)."""
    from rich.cells import cell_len

    def _w(s: str, code: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m"

    color = console.color_system is not None
    cyan   = "36"                 # ANSI Cyan (рамка, заголовок, разделители)
    purple = "38;2;214;180;255"   # пастельный фиолетовый (автор)
    green  = "38;2;90;247;142"    # зелёный #5af78e (бейдж "актуально")
    gray   = "90"                 # серый (подписи полей)

    title = f"DPI Detector v{CURRENT_VERSION}"
    top_left = f"── {title} ─"

    badge_colored = _w(badge, green) if badge == "✓ Актуальная версия" else badge
    rows_plain = [
        "  Автор: Runni • GitHub: Runnin4ik/dpi-detector",
        f"  Чат: t.me/DPI_detector • {badge}",
    ]
    # Общая ширина обводок (BOX_W — по подсказке меню); если контент шире — по нему
    W = max(BOX_W, max(cell_len(r) for r in rows_plain) + 4)
    k = (W - 2) - cell_len(top_left)
    if color:
        top = _w("╭" + top_left + "─" * k + "╮", cyan)
    else:
        top = "╭" + top_left + "─" * k + "╮"

    body = []
    for i, plain in enumerate(rows_plain):
        gap = (W - 2) - cell_len(plain)
        if not color:
            body.append("│" + plain + " " * gap + "│")
            continue
        if i == 0:
            row = (f"  {_w('Автор:', gray)} {_w('Runni', purple)}"
                   f"{_w(' • ', cyan)}"
                   f"{_w('GitHub:', gray)} Runnin4ik/dpi-detector")
        else:
            row = (f"  {_w('Чат:', gray)} t.me/DPI_detector"
                   f"{_w(' • ', cyan)}"
                   f"{badge_colored}")
        body.append(_w("│", cyan) + row + " " * gap + _w("│", cyan))
    bottom = _w("╰" + "─" * (W - 2) + "╯", cyan) if color else "╰" + "─" * (W - 2) + "╯"
    text = "\n".join([top] + body + [bottom]) + "\n"
    return text, len(text.splitlines())


def _version_badge(latest: Optional[str]) -> str:
    """Бейдж статуса обновлений для баннера."""
    if not latest:
        return "✖ Не удалось проверить обновления"
    if is_newer(latest, CURRENT_VERSION):
        return f"↑ Доступна новая версия {latest}"
    return "✓ Актуальная версия"


def _header_render(header: dict) -> str:
    """Шапка: баннер (со статусом обновлений). Инфо о сети — тест 0."""
    return header["banner"]


def _header_height(header: dict) -> int:
    return header["banner_lines"]

DOMAINS         = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()
WHITELIST_SNI   = load_whitelist_sni()

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="DPI Detector — Анализатор блокировок трафика",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--tests",       type=str, help="Список тестов для запуска (например: 123 или 24). Пропускает стартовое меню.")
    parser.add_argument("-p", "--proxy",       type=str, help="URL прокси (напр: socks5://127.0.0.1:1080) (PROXY_URL)")
    parser.add_argument("-c", "--concurrency", type=int, help="Максимальное количество параллельных запросов (MAX_CONCURRENT)")
    parser.add_argument("-d", "--domain",      type=str, action="append", help="Проверить конкретный домен(ы), игнорируя domains.txt.\nМожно указывать несколько раз: -d vk.com -d ya.ru")
    parser.add_argument("-o", "--output",      type=str, help="Путь для автосохранения отчета (например: report.txt).")
    parser.add_argument("--batch",             action="store_true", help="Отключает паузы и вопросы")
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


def _read_key_sync() -> str:
    """Блокирующее чтение одной клавиши без ожидания Enter."""
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):  # спец-клавиши (стрелки, F1-F12): второй код отбрасываем
            msvcrt.getwch()
            return "\x00"
        if ch in ("\x03", "\x04", "\x1a"):  # Ctrl+C / Ctrl+D / Ctrl+Z — выход
            raise KeyboardInterrupt
        return ch
    import termios, tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if ch in ("\x03", "\x04", "\x1a"):  # Ctrl+C / Ctrl+D / Ctrl+Z в raw-режиме
        raise KeyboardInterrupt
    return ch


async def _read_key_cancelable() -> str:
    """Одна клавиша; если stdin не терминал — строка ввода (fallback)."""
    loop = asyncio.get_running_loop()
    if sys.stdin.isatty():
        return (await loop.run_in_executor(None, _read_key_sync)).lower()
    return (await _readline_cancelable()).strip().lower()


def _selection_flags(selection: str) -> tuple:
    """Раскладывает строку выбора ('0123'...) на флаги запуска тестов."""
    run_net_info  = "0" in selection   # Тест 0: информация о сети и системе
    run_dns_avail = "1" in selection   # Тест 1: доступность DNS-серверов
    run_domains   = "2" in selection   # Тест 2: доступность доменов (TLS/HTTP)
    run_tcp       = "3" in selection   # Тест 3: TCP 16-20KB блокировка
    run_wl_sni    = "4" in selection   # Тест 4: белые SNI для ASN
    run_telegram  = "5" in selection   # Тест 5: Telegram
    run_legend    = "6" in selection   # Тест 6: Легенда
    only_legend   = run_legend and not any([
        run_dns_avail, run_domains, run_tcp, run_wl_sni, run_telegram
    ])
    return (run_net_info, run_dns_avail, run_domains, run_tcp,
            run_wl_sni, run_telegram, run_legend, only_legend)



def _format_summary(
    run_dns_avail: bool,
    run_domains: bool,
    run_tcp: bool,
    run_telegram: bool,
    domain_stats,
    tcp_stats,
    telegram_stats=None,
    dns_avail_stats=None,
) -> Optional[Table]:
    # Пары (левая подпись, значение) — рендерятся таблицей с автопереносом
    items: list[tuple[str, str]] = []

    # ── Тест 1: доступность DNS ───────────────────────────────────────────────
    if run_dns_avail:
        if dns_avail_stats:
            d = dns_avail_stats
            doh_color = "green" if d["doh_ok"] == d["doh_total"] else (
                "red" if d["doh_ok"] == 0 else "yellow"
            )
            udp_color = "green" if d["udp_ok"] == d["udp_total"] else (
                "red" if d["udp_ok"] == 0 else "yellow"
            )
            dot_ok, dot_total = d.get("dot_ok", 0), d.get("dot_total", 0)
            dot_color = "green" if dot_ok == dot_total else (
                "red" if dot_ok == 0 else "yellow"
            )
            dns_parts = [f"[{doh_color}]{d['doh_ok']}/{d['doh_total']} DoH[/{doh_color}]"]
            if dot_total:
                dns_parts.append(f"[{dot_color}]{dot_ok}/{dot_total} DoT[/{dot_color}]")
            dns_parts.append(f"[{udp_color}]{d['udp_ok']}/{d['udp_total']} UDP[/{udp_color}]")
            items.append(("DNS доступность", "  ".join(dns_parts)))
            if d.get("hijacked_brands"):
                total_r = d.get("resolvers_total", 0)
                if total_r and len(d["hijacked_brands"]) >= total_r:
                    items.append(("Подмена резолвера", "[red]Все[/red]"))
                else:
                    items.append(("Подмена резолвера",
                        f"[red]{', '.join(d['hijacked_brands'])}[/red]"))
            else:
                items.append(("Подмена резолвера", "[dim]—[/dim]"))
            if d.get("subst_total"):
                fi = d.get("fakeip_sub", 0)
                if fi:
                    items.append(("FakeIP ответов",
                        f"у [magenta]{fi}/{d['subst_total']}[/magenta] UDP"))
                rest = d.get("subst_sub", 0) - fi
                if rest > 0:
                    color = "red" if rest == d["subst_total"] else "yellow"
                    items.append(("Подмена ответов",
                        f"у [{color}]{rest}/{d['subst_total']}[/{color}] UDP"))
                elif not fi:
                    items.append(("Подмена ответов",
                        f"у [green]0/{d['subst_total']}[/green] UDP"))
        else:
            items.append(("DNS доступность", "[dim]—[/dim]"))

    # ── Тест 2: домены ────────────────────────────────────────────────────────
    if domain_stats:
        d = domain_stats

        def _stat(label, ok):
            color = "green" if ok == d["total"] else ("red" if ok == 0 else "yellow")
            return f"[{color}]{ok}/{d['total']} {label}[/{color}]"

        items.append(("Домены",
            _stat("HTTP", d["http_ok"])
            + f"  {_stat('TLS1.2', d['t12_ok'])}"
            + f"  {_stat('TLS1.3', d['t13_ok'])}"))

    # ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────────
    if tcp_stats:
        t = tcp_stats
        pct = int(t["ok"] / t["total"] * 100) if t["total"] else 0
        value = (
            f"[green]√ {t['ok']}/{t['total']} OK[/green]"
            + (f"  [red]× {t['blocked']} блок.[/red]" if t['blocked'] else "")
            + (f"  [yellow]≈ {t['mixed']} смеш.[/yellow]" if t['mixed'] else "")
            + f"  [dim]({pct}% ОК)[/dim]"
        )
        items.append(("TCP 16-20KB", value))

    # ── Тест 5: Telegram ──────────────────────────────────────────────────────
    if run_telegram and telegram_stats:
        t = telegram_stats
        dl_data = t.get("download", {})
        ul_data = t.get("upload", {})
        dc_r, dc_t = t.get("dc_reachable", 0), t.get("dc_total", 0)

        def _fmt_tg(label, data, speed_key, size_key):
            st   = data.get("status")
            avg  = data.get(speed_key, 0)
            size = data.get(size_key, 0)
            drop = data.get("drop_at_sec")
            if st == "ok":
                raw_st, color = "ОК", "green"
            elif st == "stalled":
                raw_st, color = "ЗАМЕДЛЕНИЕ+ОБРЫВ", "yellow"
            elif st == "slow":
                raw_st, color = "ЗАМЕДЛЕНИЕ", "yellow"
            elif st == "blocked":
                raw_st, color = "НЕДОСТУПНО", "red"
            else:
                raw_st, color = "ОШИБКА", "red"
            metrics = f"ср. {_tg_fmt(avg)}, {_tg_size(size)}"
            if drop:
                metrics += f", обрыв на {drop}с"
            return label, f"[{color}]{raw_st:<16}[/{color}] {metrics}"

        items.append(_fmt_tg("TG Скачивание", dl_data, "avg_bps", "bytes_total"))
        items.append(_fmt_tg("TG Загрузка",   ul_data, "bps",     "sent"))
        dc_color = "green" if dc_r == dc_t else ("red" if dc_r == 0 else "yellow")
        items.append(("TG Датацентры", f"[{dc_color}]ОК {dc_r}/{dc_t}[/{dc_color}]"))

    # ── Таблица: подпись не переносится, значение переносится на узких терминалах
    if not items:
        return None
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(no_wrap=True)
    t.add_column()
    for lab, val in items:
        t.add_row(f"[bold]{lab}[/bold]", val)
    return t


def _export_report(result_path: str) -> None:
    """Сохраняет весь выведенный в консоль текст в файл."""
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            f.write(console.export_text())
        console.print(f"[dim]Результаты сохранены: [cyan]{result_path}[/cyan][/dim]")
    except Exception as e:
        console.print(f"[yellow]Не удалось сохранить файл: {e}[/yellow]")



def is_newer(latest: str, current: str) -> bool:
    try:
        def parse(v):
            return tuple(int(x) for x in v.replace('v', '').split('.') if x.isdigit())
        return parse(latest) > parse(current)
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

    # ── Шапка: баннер (фикс. ширина) + лениво подгружаемые инфо/версия ──
    banner, banner_lines = _render_banner()
    header = {
        "banner": banner, "banner_lines": banner_lines,
        "net_text": None, "net_lines": 0,
    }

    version_task = asyncio.create_task(_fetch_latest_version())

    async def _net_updater() -> None:
        """Сбор инфо для теста 0 («Информация о сети и системе»)."""
        try:
            dns_info = get_system_dns()
            bypass   = detect_bypass_tools()

            def _publish(info: dict) -> None:
                text, lines = _render_net_info_block(info, dns_info, bypass)
                header["net_text"], header["net_lines"] = text, lines

            _publish({})          # 1) скелет: все поля "…"
            try:
                ip, ttlb = await _fetch_public_ip()
            except Exception:
                ip, ttlb = None, None
            if not ip:
                _publish({"ip": "timeout", "ttlb_ms": "timeout",
                          "subnet": "timeout", "org": "timeout", "cc": "timeout"})
                return
            _publish({"ip": ip, "ttlb_ms": ttlb})   # 2) внешний IP пришёл
            try:
                extra = await _fetch_ip_info(ip)
            except Exception:
                extra = {}
            info = {"ip": ip, "ttlb_ms": ttlb}
            info.update({k: (v if v is not None else "timeout") for k, v in extra.items()})
            for k in ("subnet", "org", "cc"):
                info.setdefault(k, "timeout")
            _publish(info)         # 3) Cymru: org/asn/subnet/cc

            # 4) upstream роутера: активный DNS == шлюз → роутер-релей (dnsmasq и т.п.)
            gw = dns_info.get("gateway")
            active_ips = {ip for ip, _ in dns_info.get("active", [])}
            if gw and gw in active_ips:
                up = await probe_resolver_ip(gw)
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
                    _publish(info)
        except Exception:
            pass

    async def _version_updater() -> None:
        try:
            latest = await asyncio.wait_for(asyncio.shield(version_task), timeout=4.0)
        except Exception:
            latest = None
        banner, banner_lines = _render_banner(_version_badge(latest))
        header["banner"], header["banner_lines"] = banner, banner_lines

    net_task = None   # создаётся только при выборе теста 0 (инфо о сети)
    ver_task = asyncio.create_task(_version_updater())

    if args.tests:
        selection = args.tests
        # без меню — ждём версию и печатаем шапку целиком
        try:
            await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
        except Exception:
            pass
        sys.stdout.write(_header_render(header))
        sys.stdout.flush()
    else:
        if sys.stdin is None or not sys.stdin.isatty():
            # пайп/CI: интерактивного обновления нет — ждём и печатаем сразу
            try:
                await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
            except Exception:
                pass
            sys.stdout.write(_header_render(header))
            sys.stdout.flush()
        selection = await ask_test_selection(
            header_state=header, version_task=ver_task,
        )

    console.print(
        f"[dim]Семейство IP: [cyan]{getattr(config, 'IP_VERSION', 'ipv4')}[/cyan]"
        f" | Параллельных запросов: [cyan]{config.MAX_CONCURRENT}[/cyan][/dim]"
    )
    if config.PROXY_URL:
        console.print(f"[dim]Используется прокси: [yellow]{config.PROXY_URL}[/yellow][/dim]")

    (run_net_info, run_dns_avail, run_domains, run_tcp,
     run_wl_sni, run_telegram, run_legend, only_legend) = _selection_flags(selection)

    if only_legend:
        while True:
            print_legend()
            if sys.stdin is None or not sys.stdin.isatty():
                return                     # пайп/CI — сразу
            console.print(Panel(
                "[bold white not dim on dark_green]  Enter  [/] Повторить   "
                "[bold white not dim on dark_blue]  M  [/] Меню   "
                "[bold white not dim on dark_red]  Q  [/] Выход",
                style="dim", box=box.HORIZONTALS,
            ))
            _flush_stdin()
            try:
                key = await _read_key_cancelable()
            except KeyboardInterrupt:
                raise
            if key in ("m", "ь", "v", "м"):
                selection = await ask_test_selection()
                (run_net_info, run_dns_avail, run_domains, run_tcp,
                 run_wl_sni, run_telegram, run_legend, only_legend) = _selection_flags(selection)
                if not only_legend:
                    break                  # выбран другой тест — идём в основной поток
                console.print()
            elif key in ("q", "й"):
                raise SystemExit(0)
            # Enter и прочие клавиши — повторить легенду
    # IPv6-режим на машине без IPv6: пробы тихо ушли бы по IPv4 (фолбэк
    # DoT/DoH на доменное имя) — запрещаем тест сразу, честно.
    if getattr(config, "IP_VERSION", "ipv4") == "ipv6" and not ipv6_supported():
        console.print(
            "[red]Ошибка: выбран режим IPv6, но IPv6 не настроен в системе.[/red]"
            "\n[dim]Переключите семейство на IPv4: IP_VERSION: ipv4 в config.yml"
            " или стрелки ← → в меню.[/dim]"
        )
        return

    # ── Подтверждение выбора перед стартом ───────────────────────────────────
    selected_names = []
    if run_dns_avail: selected_names.append("DNS-серверы")
    if run_domains:   selected_names.append("Домены")
    if run_tcp:       selected_names.append("TCP 16-20KB")
    if run_wl_sni:    selected_names.append("Белые SNI")
    if run_net_info:  selected_names.append("Информация о сети")
    if run_telegram:  selected_names.append("Telegram")
    if selected_names:
        console.print(f"[dim]Будут запущены: [cyan]{', '.join(selected_names)}[/cyan][/dim]")

    # Автосохранение только через -o; иначе — экспорт по [S] после тестов
    result_path = args.output

    while True:
        # Экспорт ([S]/-o) — только результаты текущего прогона,
        # без меню/шапки/служебных строк
        reset_record()
        # Семафор пересоздаётся каждую итерацию: конкурентность можно сменить в меню
        semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)

        # ── stub-заглушки для теста доменов (минимальная проверка) ──────────
        stub_ips: set = set()
        if run_domains:
            try:
                stub_ips = await asyncio.wait_for(
                    collect_stub_ips_silently(),
                    timeout=config.STUB_IPS_TIMEOUT
                )
            except asyncio.TimeoutError:
                stub_ips = set()

        # ── Тест 0: информация о сети и системе ─────────────────────────────
        if run_net_info:
            if net_task is None:   # лениво: сбор только по выбору теста 0
                net_task = asyncio.create_task(_net_updater())
            try:
                await asyncio.wait_for(asyncio.shield(net_task), timeout=6.0)
            except Exception:
                pass
            net_text = header.get("net_text")
            if net_text:
                # Панель уже отрендерена (ANSI) — печатаем сырьём, как шапку;
                # console.print пережевал бы ESC-коды как markup (мусор)
                if sys.stdout.isatty():
                    sys.stdout.write(net_text)
                else:
                    sys.stdout.write(re.sub(r"\x1b\[[0-9;]*m", "", net_text))
                sys.stdout.flush()
            else:
                console.print("[yellow]Информация о сети недоступна.[/yellow]")
            # В пачке с другими тестами — пауза, чтобы панель не пролетела
            if run_dns_avail or run_domains or run_tcp or run_wl_sni or run_telegram:
                await asyncio.sleep(2.0)

        # ── Тест 1: доступность DNS-серверов ─────────────────────────────────
        dns_avail_stats = None
        if run_dns_avail:
            dns_avail_stats = await check_dns_availability()

        # ── Тест 2: домены ────────────────────────────────────────────────────
        domain_stats = None
        if run_domains:
            domain_stats = await run_domains_test(semaphore, stub_ips, DOMAINS)

        # ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────
        tcp_stats = None
        if run_tcp:
            tcp_stats = await run_tcp_test(semaphore, TCP_16_20_ITEMS)

        # ── Тест 4: белые SNI ─────────────────────────────────────────────────
        if run_wl_sni:
            if WHITELIST_SNI:
                await run_whitelist_sni_test(semaphore, TCP_16_20_ITEMS, WHITELIST_SNI)
            else:
                console.print("[yellow]Файл whitelist_sni.txt пуст или не найден — тест 5 пропущен.[/yellow]")

        # ── Тест 5: Telegram ──────────────────────────────────────────────────
        telegram_stats = None
        if run_telegram:
            telegram_stats = await run_telegram_test(semaphore)

        # ── Итоговая сводка ───────────────────────────────────────────────────
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

        if args.batch:
            break

        console.print(Panel(
            "[bold white not dim on dark_green]  Enter  [/] Повторить   "
            "[bold white not dim on dark_blue]  M  [/] Меню   "
            "[bold white not dim on yellow]  S  [/] Экспорт   "
            "[bold white not dim on dark_red]  Q  [/] Выход",
            style="dim", box=box.HORIZONTALS,
        ))
        _flush_stdin()
        while True:
            try:
                key = await _read_key_cancelable()
            except KeyboardInterrupt:
                raise
            if key in ("m", "ь", "v", "м"):   # M и V на английской и русской раскладках
                console.print()
                while True:
                    selection = await ask_test_selection()
                    (run_net_info, run_dns_avail, run_domains, run_tcp,
                     run_wl_sni, run_telegram, run_legend, only_legend) = _selection_flags(selection)
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
                _flush_stdin()          # накликанное в меню не утечёт дальше
                break
            if key in ("q", "й"):       # явный выход
                raise SystemExit(0)
            if key in ("s", "ы"):       # экспорт отчёта на лету
                if not result_path:
                    result_path = os.path.join(get_base_dir(), "dpi_detector_results.txt")
                _export_report(result_path)
                continue
            if key in ("\r", "\n", ""):   # Enter — повторить
                break
            console.print("[yellow]Нажмите [Enter] для повтора, [M]/[V] для меню, [S] для экспорта, [Q] для выхода[/yellow]")
        console.print()


def check_dependencies() -> None:
    """PyInstaller не видит ленивые импорты (h2, socksio) — собранная без
    extras сборка падает только на тесте 2 с безликим CONN ERR. Проверяем
    всё явно и не даём запуститься с неполным окружением."""
    required = [
        ("h2", "h2 — HTTP/2 для DoH (pip install httpx[http2])"),
        ("socksio", "socksio — SOCKS-прокси (pip install httpx[socks])"),
        ("hpack", "hpack — HTTP/2 (ставится вместе с h2)"),
        ("yaml", "PyYAML (pip install pyyaml)"),
        ("rich", "rich (pip install rich)"),
    ]
    missing = []
    for mod, hint in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(hint)
    if missing:
        console.print("[bold red]Сборка неполная — отсутствуют модули:[/bold red]")
        for hint in missing:
            console.print(f"  [red]×[/red] {hint}")
        console.print("\n[bold yellow]Скачайте официальный релиз:[/bold yellow] "
                      f"[cyan]https://github.com/{GITHUB_REPO}/releases[/cyan]")
        try:
            input("Enter для выхода...")
        except EOFError:
            pass
        sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, fast_exit_handler)
    check_dependencies()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        fast_exit_handler(None, None)  # Ctrl+C/Ctrl+D у промпта приходят символом, не SIGINT
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
        traceback.print_exc()
        if sys.platform == 'win32':
            print("\nНажмите Enter для выхода...")
            input()
        os._exit(1)