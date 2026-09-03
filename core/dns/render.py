"""Построение и визуализация Rich-таблиц результатов DNS-тестирования."""

from typing import Dict, List, Set, Tuple
from rich.table import Table

from cli.console import console
from utils.network import get_fake_ip_type
from core.dns.stubs import _known_resolver


def _net24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def _brand(nm: str) -> str:
    return nm.split(" (", 1)[0].strip()


_DOMESTIC_BRANDS = {"msk-ix", "нсди"}


def _is_domestic(name: str) -> bool:
    return _brand(name).lower() in _DOMESTIC_BRANDS


def render_dns_availability_results(
    allowed: List[str],
    forbidden: List[str],
    raw: dict,
    fail_reasons: dict,
    doh_answers: dict,
    udp_answers: dict,
    dot_answers: dict,
    egress: dict,
    org_names: Dict[str, str],
    all_names: List[str],
    doh_servers: List[tuple],
    udp_servers: List[tuple],
    dot_servers: List[tuple],
    doh_by_name: Dict[str, List[str]],
    udp_by_name: Dict[str, List[str]],
    dot_by_name: Dict[str, List[str]],
) -> dict:
    """Формирует Rich-таблицу доступности DNS, печатает её в консоль и возвращает статистику."""

    def _org_label(eip: str) -> str:
        name = org_names.get(eip)
        if not name:
            return eip
        return name.split(" - ", 1)[0].strip() or name

    net_brands: Dict[str, Set[str]] = {}
    for (_ekind, _eaddr, ename), eip in egress.items():
        if not eip or eip == "0.0.0.0" or get_fake_ip_type(eip) == "fakeip":
            continue
        net_brands.setdefault(_net24(eip), set()).add(_brand(ename))

    def _is_hijacked(eip: str) -> bool:
        return len(net_brands.get(_net24(eip), ())) >= 2

    def _allowed_vals(a: str, name: str) -> Tuple[list, int]:
        dm = raw.get(("udp", a, name), {})
        vals = [dm[d] for d in allowed if dm.get(d) is not None]
        return vals, len(allowed)

    def _latency_cell(kind: str, name: str) -> str:
        if kind == "udp":
            addrs = udp_by_name.get(name, [])
        elif kind == "dot":
            addrs = dot_by_name.get(name, [])
        else:
            addrs = doh_by_name.get(name, [])
        if not addrs:
            return "[dim]—[/dim]"

        if kind == "udp":
            lines = []
            for a in addrs:
                vals, total_q = _allowed_vals(a, name)
                ok_q = len(vals)
                if not vals:
                    lines.append("[red]TIMEOUT[/red]")
                    continue
                ratio = f" [dim]{ok_q}/{total_q}[/dim]" if ok_q < total_q else ""
                lines.append(f"[green]{round(min(vals), 1)}мс[/green]{ratio}")
            return "\n".join(lines)

        lines = []
        for a in addrs:
            dm = raw.get((kind, a, name), {})
            vals = [v for v in dm.values() if v is not None]
            if not vals:
                reason = fail_reasons.get((kind, a, name))
                lines.append(reason if reason else "[red]TIMEOUT[/red]")
                continue
            total_q = len(dm)
            ok_q = len(vals)
            ratio = f" [dim]{ok_q}/{total_q}[/dim]" if ok_q < total_q else ""
            lines.append(f"[green]{round(min(vals), 1)}мс[/green]{ratio}")
        return "\n".join(lines)

    def _egress_cell(pname: str) -> str:
        addrs = udp_by_name.get(pname, [])
        if not addrs:
            return "[dim]—[/dim]"
        lines = []
        for a in addrs:
            vals, _ = _allowed_vals(a, pname)
            eip = egress.get(("egress", a, pname))
            if not vals:
                lines.append(f"[dim]{a}: таймаут[/dim]")
            elif not eip or eip == "0.0.0.0":
                lines.append(f"[dim]{a}: выход н/д[/dim]")
            elif get_fake_ip_type(eip) == "fakeip":
                lines.append(f"[magenta]{a}→FakeIP[/magenta]")
            elif _is_domestic(pname):
                lines.append(f"{a}→{_org_label(eip)}")
            elif _known_resolver(_org_label(eip)):
                lines.append(f"[green]{a}→{_org_label(eip)}[/green]")
            else:
                lines.append(f"[red]{a}→{_org_label(eip)}[/red]")
        return "\n".join(lines)

    def _collect_truth() -> Dict[str, Set[str]]:
        truth: Dict[str, Set[str]] = {}
        for (kind, _addr, _name, d), parsed in doh_answers.items():
            if kind != "doh_wire":
                continue
            if isinstance(parsed, list) and parsed:
                real = [ip for ip in parsed if get_fake_ip_type(ip) != "fakeip"]
                if real:
                    truth.setdefault(d, set()).update(real)
        for (_kind, _addr, _name, d), parsed in dot_answers.items():
            if isinstance(parsed, list) and parsed:
                real = [ip for ip in parsed if get_fake_ip_type(ip) != "fakeip"]
                if real:
                    truth.setdefault(d, set()).update(real)
        return truth

    truth_ips = _collect_truth()

    def _udp_server_available(a: str, name: str) -> bool:
        dm = raw.get(("udp", a, name), {})
        return any(dm.get(d) is not None for d in allowed)

    def _udp_ips(a: str, name: str, domain: str) -> set:
        p = udp_answers.get(("udp", a, name, domain))
        return set(p) if isinstance(p, list) else set()

    def _fakeip_sub(a: str, name: str) -> int:
        n = 0
        for d in forbidden:
            ips = _udp_ips(a, name, d)
            if ips and any(get_fake_ip_type(ip) == "fakeip" for ip in ips):
                n += 1
        return n

    def _subst_counts(a: str, name: str) -> Tuple[int, int]:
        if not _udp_server_available(a, name):
            return (0, 0)
        judged = sub = 0
        for d in forbidden:
            truth = truth_ips.get(d)
            if not truth:
                continue
            judged += 1
            if not (_udp_ips(a, name, d) & truth):
                sub += 1
        return judged, sub

    def _subst_line(a: str, name: str) -> str:
        judged, sub = _subst_counts(a, name)
        if judged == 0:
            return "[dim]—[/dim]"
        frac = f"{sub}/{len(forbidden)}"
        if _fakeip_sub(a, name) > 0:
            return f"[magenta]{frac}[/magenta]"
        if sub == len(forbidden):
            return f"[red]{frac}[/red]"
        if sub == 0:
            return f"[green]{frac}[/green]"
        return f"[yellow]{frac}[/yellow]"

    def _subst_cell(name: str) -> str:
        addrs = udp_by_name.get(name, [])
        if not addrs or not forbidden:
            return "[dim]—[/dim]"
        return "\n".join(_subst_line(a, name) for a in addrs)

    # ── Построение таблицы ──
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Провайдер", style="cyan", no_wrap=True, min_width=16)
    t.add_column("DoH мин", justify="right", no_wrap=True)
    if dot_servers:
        t.add_column("DoT мин", justify="right", no_wrap=True)
    t.add_column("UDP мин", justify="right", no_wrap=True)
    t.add_column("Реальный UDP резолвер", no_wrap=True)
    t.add_column("Подмена", justify="right", no_wrap=True)

    doh_ok_cnt = sum(
        1 for a, n, _ in doh_servers
        if any(v is not None for v in raw.get(("doh_wire", a, n), {}).values())
    )
    udp_ok_cnt = sum(
        1 for a, n, _ in udp_servers
        if any(raw.get(("udp", a, n), {}).get(d) is not None for d in allowed)
    )
    dot_ok_cnt = sum(
        1 for a, n, _ in dot_servers
        if any(v is not None for v in raw.get(("dot", a, n), {}).values())
    )

    for name in all_names:
        cells = [_latency_cell("doh_wire", name)]
        if dot_servers:
            cells.append(_latency_cell("dot", name))
        cells += [_latency_cell("udp", name), _egress_cell(name), _subst_cell(name)]
        n_rows = max((len(c.splitlines()) for c in cells), default=1)
        name_cell = "\n".join(name if i == 0 else f"{name} #{i + 1}" for i in range(n_rows))
        t.add_row(name_cell, *cells)

    try:
        meas = t.__rich_measure__(console, console.options)
        wide = max(console.width, int(meas.maximum) + 2)
        console.print(t, width=wide)
    except Exception:
        console.print(t)

    # ── Вычисление статистики ──
    hi_brand_set: Set[str] = set()
    for hname, haddrs in udp_by_name.items():
        for ha in haddrs:
            heip = egress.get(("egress", ha, hname))
            if heip and heip != "0.0.0.0" and _is_hijacked(heip) \
                    and not _known_resolver(_org_label(heip)) \
                    and not _is_domestic(hname):
                hi_brand_set.add(_brand(hname))
    hijacked_brands = sorted(hi_brand_set)
    console.print()

    resolvers_total = len({_brand(n) for n in udp_by_name if not _is_domestic(n)})

    subst_sub = subst_total = 0
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            j, s = _subst_counts(sa, snm)
            if j:
                subst_total += 1
                if s:
                    subst_sub += 1

    stub_ip_counts: Dict[str, int] = {}
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            if not _udp_server_available(sa, snm):
                continue
            for d in forbidden:
                truth = truth_ips.get(d)
                if not truth:
                    continue
                uips = _udp_ips(sa, snm, d)
                if uips and not (uips & truth):
                    for ip in uips:
                        stub_ip_counts[ip] = stub_ip_counts.get(ip, 0) + 1
    top_stub = max(stub_ip_counts, key=stub_ip_counts.get) if stub_ip_counts else None

    fakeip_sub = 0
    for snm, saddrs in udp_by_name.items():
        for sa in saddrs:
            j, _ = _subst_counts(sa, snm)
            if j and _fakeip_sub(sa, snm) > 0:
                fakeip_sub += 1
    fakeip_total = subst_total

    if subst_sub > 0:
        console.print()
        if top_stub and get_fake_ip_type(top_stub) == "fakeip":
            console.print(
                "[bold magenta][!] DNS-ответы содержат FakeIP[/bold magenta]\n"
                "Для честной оценки DNS отключите прокси/FakeIP на время проверки."
            )
        else:
            console.print(
                "[bold yellow][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold yellow]\n"
                "Провайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY/TIMEOUT\n"
                + (f"IP адрес заглушки провайдера - {top_stub}.\n" if top_stub else "")
                + "Рекомендация: настройте DoH на устройстве/роутере, если еще не сделали этого."
            )

    return {
        "doh_ok":          doh_ok_cnt,
        "doh_total":       len(doh_servers),
        "dot_ok":          dot_ok_cnt,
        "dot_total":       len(dot_servers),
        "udp_ok":          udp_ok_cnt,
        "udp_total":       len(udp_servers),
        "hijacked_brands": hijacked_brands,
        "resolvers_total": resolvers_total,
        "subst_sub":       subst_sub,
        "subst_total":     subst_total,
        "fakeip_sub":      fakeip_sub,
        "fakeip_total":    fakeip_total,
    }
