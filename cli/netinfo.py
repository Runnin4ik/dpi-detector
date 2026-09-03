import asyncio
import ipaddress
import re
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

import httpx
from rich import box
from rich.cells import cell_len
from rich.panel import Panel
from rich.text import Text

from utils import config
from utils.network import pin_host, get_fake_ip_type
from core.dns_scanner import _build_dns_query, _parse_txt_response
from cli.ui import BOX_W

_CYMRU_DOH_URLS = tuple(getattr(config, "CYMRU_DOH_SERVERS",
                                ("https://dns.google/dns-query",
                                 "https://cloudflare-dns.com/dns-query",
                                 "https://common.dot.dns.yandex.net/dns-query")))

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
                except Exception as e:
                    logger.debug("IP lookup endpoint %s failed: %s", u, e)
                return None, None

            tasks = [asyncio.create_task(_check_one(u)) for u in urls]
            try:
                for fut in asyncio.as_completed(tasks):
                    ip, ttlb = await fut
                    if ip:
                        return ip, ttlb
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
        return None, None

    (v4_res, v6_res) = await asyncio.gather(_lookup_first(v4_urls, 4), _lookup_first(v6_urls, 6))
    return {"v4": v4_res, "v6": v6_res}


async def _fetch_ip_info(ip: str, timeout: float = 5.0) -> dict:
    """Team Cymru через DoH (RFC 8484 POST, IPv4 и IPv6): {asn, subnet, cc, org}. Ошибка → {}."""
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
            except Exception as e:
                logger.debug("Cymru origin query to %s failed: %s", url, e)
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
                except Exception as e:
                    logger.debug("Cymru AS name query to %s failed: %s", url, e)
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
    """Строки блока 'Информация о сети и системе' (с rich-разметкой)."""
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
        iface_shown = bool(a_name and a_ip)
        doh    = (sys_dns or {}).get("doh", {})
        def mark(ips):
            return [ip + "(DoH)" if ip in doh else ip for ip in ips]

        ips_all = [ip for ip, _ in active]
        srcs = {src for _, src in active}
        src_label = ""
        if any(get_fake_ip_type(ip) == "fakeip" for ip in ips_all):
            src_label = "fake-ip"
        elif _is_tun_name(a_name):
            src_label = "TUN"
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
    width = max(BOX_W, max(cell_len(Text.from_markup("  " + l).plain) for l in lines) + 6)
    return Panel(
        "\n".join("  " + l for l in lines),
        title="Информация о сети и системе",
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
        width=width,
    )
