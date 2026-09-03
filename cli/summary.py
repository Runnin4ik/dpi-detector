from typing import Optional, List, Tuple
from rich.table import Table
from cli.console import console
from core.telegram_scanner import _fmt_speed as _tg_fmt, _fmt_size as _tg_size


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
    """Строит сводную таблицу результатов сканирования."""
    items: List[Tuple[str, str]] = []

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
