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
import ipaddress
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
    _build_dns_query,
    _parse_txt_response,
)
from utils.network import ipv6_supported, is_local_or_relay_ip
from utils.files import load_domains, load_tcp_targets, load_whitelist_sni, get_base_dir
from utils.system_check import get_system_dns, detect_bypass_tools

CURRENT_VERSION = "4.0.10"
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


async def _fetch_public_ips(timeout: float = 3.5) -> dict:
    """Внешние IPv4 и IPv6 адреса + TTLB (мс).
    Возвращает {'v4': (ip4, ttlb4), 'v6': (ip6, ttlb6)}.
    """
    v4_urls = getattr(config, "IP4_LOOKUP_URLS",
                      getattr(config, "IP_LOOKUP_URLS",
                              ("https://api4.ipify.org", "https://api.ipify.org",
                               "https://v4.ident.me", "https://ipv4.icanhazip.com")))
    v6_urls = getattr(config, "IP6_LOOKUP_URLS",
                      ("https://api64.ipify.org", "https://icanhazip.com",
                       "https://ifconfig.me/ip", "https://v6.ident.me"))
    proxy_url = getattr(config, "PROXY_URL", None)

    async def _lookup_first(urls, expected_ver: int) -> tuple:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     trust_env=False, proxy=proxy_url) as client:
            async def _check_one(u: str) -> tuple:
                try:
                    resp = await client.get(u)
                    if resp.status_code == 200:
                        cand = resp.text.strip()
                        ip_obj = ipaddress.ip_address(cand)
                        if ip_obj.version == expected_ver and not ip_obj.is_private:
                            return str(ip_obj), int((time.perf_counter() - t0) * 1000)
                except Exception:
                    pass
                return None, None

            tasks = [asyncio.create_task(_check_one(u)) for u in urls]
            for fut in asyncio.as_completed(tasks):
                ip, ttlb = await fut
                if ip:
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    return ip, ttlb
        return None, None

    (v4_res, v6_res) = await asyncio.gather(_lookup_first(v4_urls, 4), _lookup_first(v6_urls, 6))
    return {"v4": v4_res, "v6": v6_res}


async def _fetch_ip_info(ip: str, timeout: float = 5.0) -> dict:
    """Team Cymru через DoH (RFC 8484 POST, IPv4 и IPv6): {asn, subnet, cc, org}. Ошибка → {}."""
    from utils.network import pin_host
    info = {}
    if not ip or ip in ("timeout", "…"):
        return info
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return info

    if ip_obj.version == 6:
        rev = ".".join(reversed(ip_obj.exploded.replace(":", "")))
        q_name = f"{rev}.origin6.asn.cymru.com"
    else:
        rev = ".".join(reversed(ip.split(".")))
        q_name = f"{rev}.origin.asn.cymru.com"

    proxy_url = getattr(config, "PROXY_URL", None)
    tq = _build_dns_query(q_name, qtype=16)
    headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 trust_env=False, proxy=proxy_url, http2=True) as client:
        doh_urls = getattr(config, "CYMRU_DOH_SERVERS", _CYMRU_DOH_URLS)
        for url in doh_urls:
            url_pin, ehost = await pin_host(url)
            h = dict(headers)
            if ehost:
                h["Host"] = ehost
            ext = {"sni_hostname": ehost} if ehost else None
            try:
                resp = await client.post(url_pin, content=tq, headers=h, extensions=ext)
                if resp.status_code != 200:
                    continue
                txt = _parse_txt_response(resp.content)
                if not txt:
                    continue
                fields = [p.strip() for p in txt.strip('"').split("|")]
                info["asn"] = fields[0].split()[0]
                for f in fields[1:]:
                    if "/" in f:
                        info["subnet"] = f
                    elif re.fullmatch(r"[A-Z]{2}", f):
                        info["cc"] = f
                info["org"] = re.sub(r"\s+", " ", fields[-1]).strip() if fields[-1] else ""
                break
            except Exception:
                continue

        if info.get("asn"):
            as_q = _build_dns_query(f"AS{info['asn']}.asn.cymru.com", qtype=16)
            for url in doh_urls:
                url_pin, ehost = await pin_host(url)
                h = dict(headers)
                if ehost:
                    h["Host"] = ehost
                ext = {"sni_hostname": ehost} if ehost else None
                try:
                    resp = await client.post(url_pin, content=as_q, headers=h, extensions=ext)
                    if resp.status_code != 200:
                        continue
                    txt = _parse_txt_response(resp.content)
                    if not txt:
                        continue
                    fields = [p.strip() for p in txt.strip('"').split("|")]
                    name = fields[-1] if len(fields) >= 3 else fields[0]
                    org_name = re.sub(r"\s+", " ", name).strip()
                    if org_name and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", org_name):
                        info["org"] = org_name
                    break
                except Exception:
                    continue
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

    def _v(v: str) -> str:
        return f"[red]{v}[/red]" if v == "timeout" else f"[cyan]{v}[/cyan]"

    def _ttlb_str(ttlb) -> str:
        if ttlb is None:
            return "…"
        if ttlb == "timeout":
            return "[red]timeout[/red]"
        if isinstance(ttlb, int):
            return f"[dim]{ttlb} ms[/dim]"
        return str(ttlb)

    v4_info = net_info.get("v4")
    v6_info = net_info.get("v6")

    # Совместимость со старым плоским словарём {"ip": ..., "subnet": ...}
    if v4_info is None and v6_info is None and "ip" in net_info:
        old_ip = net_info.get("ip")
        if old_ip and ":" in old_ip:
            v6_info = net_info
        else:
            v4_info = net_info

    if not net_info:
        lines.append("IPv4: [cyan]…[/cyan]  Subnet: [cyan]…[/cyan]  TTLB: …")
        lines.append("IPv6: [cyan]…[/cyan]")
        lines.append("Org: [cyan]…[/cyan]")
        lines.append("Location: [cyan]…[/cyan]")
    else:
        if v4_info and v4_info.get("ip"):
            ip4 = v4_info.get("ip") or "…"
            sub4 = v4_info.get("subnet") or "…"
            ttlb4_s = _ttlb_str(v4_info.get("ttlb_ms"))
            lines.append(f"IPv4: {_v(ip4)}  Subnet: {_v(sub4)}  TTLB: {ttlb4_s}")
        else:
            lines.append("IPv4: [dim]недоступен[/dim]")

        if v6_info and v6_info.get("ip"):
            ip6 = v6_info.get("ip") or "…"
            sub6 = v6_info.get("subnet") or "…"
            ttlb6_s = _ttlb_str(v6_info.get("ttlb_ms"))
            lines.append(f"IPv6: {_v(ip6)}")
            lines.append(f"      Subnet: {_v(sub6)}  TTLB: {ttlb6_s}")
        else:
            lines.append("IPv6: [dim]недоступен[/dim]")

        v4_org = (v4_info or {}).get("org") or ""
        v4_asn = (v4_info or {}).get("asn") or ""
        v4_cc  = (v4_info or {}).get("cc") or ""

        v6_org = (v6_info or {}).get("org") or ""
        v6_asn = (v6_info or {}).get("asn") or ""
        v6_cc  = (v6_info or {}).get("cc") or ""

        if v4_org and v6_org and v4_org != v6_org:
            s4 = f"{v4_org} (AS{v4_asn})" if v4_asn else v4_org
            s6 = f"{v6_org} (AS{v6_asn})" if v6_asn else v6_org
            org_s = f"{s4} [dim](v4)[/dim], {s6} [dim](v6)[/dim]"
        else:
            main_org = v4_org or v6_org or "…"
            main_asn = v4_asn or v6_asn or ""
            org_s = f"{main_org} (AS{main_asn})" if main_asn else main_org

        lines.append(f"Org: {_v(org_s)}")

        if v4_cc and v6_cc and v4_cc != v6_cc:
            loc = f"{_flag_emoji(v4_cc)} {v4_cc} [dim](v4)[/dim], {_flag_emoji(v6_cc)} {v6_cc} [dim](v6)[/dim]"
        else:
            main_cc = v4_cc or v6_cc or "…"
            loc = f"{_flag_emoji(main_cc)} {main_cc}".strip()
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


def _net_info_panel(net_info: dict, sys_dns: dict, bypass: list) -> Optional[Panel]:
    """Возвращает Panel для блока 'Информация о сети и системе' или None."""
    lines = _net_info_lines(net_info, sys_dns, bypass)
    if not lines:
        return None
    from rich.cells import cell_len
    from rich.text import Text
    # Общая ширина обводок (BOX_W — по подсказке меню); если контент шире — по нему
    width = max(BOX_W, max(cell_len(Text.from_markup("  " + l).plain) for l in lines) + 6)
    return Panel(
        "\n".join("  " + l for l in lines),
        title="Информация о сети и системе",
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
        width=width,
    )


def _render_banner(badge: str = "Проверка обновлений...") -> tuple:
    """Баннер: Panel со стилями Rich Markup (заголовок, автор, GitHub, чат, обновления)."""
    if badge == "✓ Актуальная версия":
        badge_colored = "[#5af78e]✓ Актуальная версия[/#5af78e]"
    elif badge.startswith("↑"):
        badge_colored = f"[yellow]{badge}[/yellow]"
    elif badge.startswith("×"):
        badge_colored = f"[dim]{badge}[/dim]"
    else:
        badge_colored = f"[dim]{badge}[/dim]"

    row1 = "  [dim]Автор:[/dim] [rgb(214,180,255)]Runni[/rgb(214,180,255)] [cyan]•[/cyan] [dim]GitHub:[/dim] Runnin4ik/dpi-detector"
    row2 = f"  [dim]Чат:[/dim] t.me/DPI_detector [cyan]•[/cyan] {badge_colored}"
    panel = Panel(
        f"{row1}\n{row2}",
        title=f"DPI Detector v{CURRENT_VERSION}",
        title_align="left",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
        width=BOX_W,
    )
    return panel, 4

def _version_badge(latest: Optional[str]) -> str:
    """Бейдж статуса обновлений для баннера."""
    if not latest:
        return "× Не удалось проверить обновления"
    if is_newer(latest, CURRENT_VERSION):
        return f"↑ Доступна новая версия {latest}"
    return "✓ Актуальная версия"


def _header_render(header: dict):
    """Шапка: баннер (со статусом обновлений). Инфо о сети — тест 0."""
    return header.get("banner")


def _header_height(header: dict) -> int:
    return header.get("banner_lines", 0)

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
    console.print("\n[bold red]Прервано пользователем.[/bold red]")
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
    }

    version_task = asyncio.create_task(_fetch_latest_version())

    async def _fetch_network_panel() -> Optional[Panel]:
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

        # upstream роутера / VPN: опрашиваем локальные релеи (dnsmasq, xray, sing-box, fake-ip и т.п.)
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

    async def _version_updater() -> None:
        try:
            latest = await asyncio.wait_for(asyncio.shield(version_task), timeout=4.0)
        except Exception:
            latest = None
        banner, banner_lines = _render_banner(_version_badge(latest))
        header["banner"], header["banner_lines"] = banner, banner_lines

    ver_task = asyncio.create_task(_version_updater())

    if args.tests:
        selection = args.tests
        # без меню — ждём версию и печатаем шапку целиком
        try:
            await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
        except Exception:
            pass
        console.print(_header_render(header))
    else:
        if sys.stdin is None or not sys.stdin.isatty():
            # пайп/CI: интерактивного обновления нет — ждём и печатаем сразу
            try:
                await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
            except Exception:
                pass
            console.print(_header_render(header))
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
            panel = None
            try:
                if sys.stdout.isatty():
                    with console.status("Получение сетевых данных...", spinner="line", spinner_style="cyan"):
                        panel = await asyncio.wait_for(_fetch_network_panel(), timeout=10.0)
                else:
                    panel = await asyncio.wait_for(_fetch_network_panel(), timeout=10.0)
            except Exception:
                panel = None

            if panel:
                console.print(panel)
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