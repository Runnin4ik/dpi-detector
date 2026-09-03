from __future__ import annotations

import os
import struct
import asyncio
import base64
import time
import ssl
import logging
from typing import Optional
logger = logging.getLogger(__name__)
import httpx
from utils import config
from cli.console import console
from utils.network import pin_host, get_resolved_ip, is_ip_literal
from utils.error_classifier import classify_connect_error, classify_read_error

# ── Белый список известных резолверов ────────────────────────────────────────
# Если UDP-запрос к серверу фактически обработал резолвер из этого списка
# (выходной IP, /24 совпадает с сетью известного публичного DNS) — это подмена
# на известный резолвер, а не перехват ТСПУ: показываем зелёным, не красным.
# MSK-IX/НСДИ не включаем — отечественные, судятся отдельно как _is_domestic.


# Белый список серверов по имени (подстроки, регистр не важен): если заявленный
# DNS-сервер называется, например, "Google", его выход не считается перехватом.
# Список вынесен в config.yml (DNS_KNOWN_RESOLVER_NAMES).
from core.dns import (
    _SingleQueryProto,
    _Socks5UdpRelay,
    _build_dns_query,
    _dns_name_sort_key,
    _doh_exc_status,
    _doh_url_with_port,
    _known_resolver,
    _load_asn_cache,
    _lookup_asn_name,
    _parse_dns_response,
    _parse_socks_proxy,
    _parse_txt_response,
    _probe_udp_all,
    _resolve_udp_native,
    _save_asn_cache,
    _skip_dns_name,
    _split_dot_endpoint,
    create_dot_ssl_context,
    _unwrap_socks_udp,
    collect_stub_ips_silently,
    probe_resolver_ip,
    resolve_asn_names,
)
from core.dns.render import render_dns_availability_results

__all__ = [
    "_SingleQueryProto",
    "_Socks5UdpRelay",
    "_build_dns_query",
    "_dns_name_sort_key",
    "_doh_exc_status",
    "_doh_url_with_port",
    "_known_resolver",
    "_load_asn_cache",
    "_lookup_asn_name",
    "_parse_dns_response",
    "_parse_socks_proxy",
    "_parse_txt_response",
    "_probe_udp_all",
    "_resolve_udp_native",
    "_save_asn_cache",
    "_skip_dns_name",
    "_split_dot_endpoint",
    "_unwrap_socks_udp",
    "check_dns_availability",
    "collect_stub_ips_silently",
    "probe_resolver_ip",
    "resolve_asn_names",
]

async def check_dns_availability() -> dict:
    """
    Тест 1: доступность DNS-серверов + пинг + детект подмены.

    Двух-фазная схема (чтобы пинги и детект подмены не конфликтовали):
      Фаза A (UDP): доверенные домены (вне цензуры) — по ним меряем пинг
                    и считаем, что сервер вообще жив.
      Фаза B (UDP): если сервер жив — те же серверы опрашиваются по
                    запрещённым доменам; сравнение UDP-ответа с DoH-правдой
                    выявляет подмену. "Молчание" на запрещённом домене тоже
                    считается подменой (блок без ответа), а не недоступностью.

    DoH (Wire) сразу проверяет запрещённые домены — это эталон "правды",
    с которым сравниваются UDP-ответы. Один TLS-коннект на сервер, запросы
    последовательно (фикс плоских 300мс ТСПУ).

    Таблица: Провайдер | DoH мин | UDP мин | Реальный UDP резолвер | Подмена
    """
    servers = getattr(config, "DNS_AVAILABILITY_SERVERS", [])
    # Доверенные домены (не под цензурой) — по ним пинг и доступность
    allowed = getattr(config, "DNS_AVAILABILITY_DOMAINS", ["vk.ru", "gosuslugi.ru"])
    # Запрещённые домены (из теста 1) — по ним выявляем подмену
    forbidden = getattr(config, "DNS_CHECK_DOMAINS", [])
    timeout = getattr(config, "DNS_AVAILABILITY_TIMEOUT", config.DNS_CHECK_TIMEOUT)

    if not servers:
        console.print("[yellow]DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.[/yellow]")
        return {"doh_ok": 0, "doh_total": 0, "dot_ok": 0, "dot_total": 0,
                "udp_ok": 0, "udp_total": 0,
                "hijacked_brands": [], "resolvers_total": 0}

    proxy_url = getattr(config, "PROXY_URL", None)
    socks_proxy = _parse_socks_proxy(proxy_url) if proxy_url else None

    # ── Группируем серверы ────────────────────────────────────────────────────
    # Запись: [адрес, имя, тип, порт?] — 4-й элемент опционален
    # (по умолчанию: UDP 53, DoH 443, DoT 853) — для нестандартных портов.
    def _entry_port(s: list, default: int) -> int:
        try:
            return int(s[3]) if len(s) > 3 else default
        except (TypeError, ValueError):
            return default

    udp_servers  = [(s[0], s[1], _entry_port(s, 53)) for s in servers if s[2] == "udp"]
    wire_servers = [(s[0], s[1], _entry_port(s, 443)) for s in servers if s[2] == "doh_wire"]
    doh_servers  = wire_servers  # только Wire
    dot_servers  = [(s[0], s[1], _entry_port(s, 853)) for s in servers if s[2] == "dot"]



    # ── Уникальные имена провайдеров в порядке появления ─────────────────────
    all_names: list[str] = []
    seen: set[str] = set()
    for _, n, _ in (doh_servers + udp_servers + dot_servers):
        if n not in seen:
            all_names.append(n)
            seen.add(n)
    # Ручной порядок: популярные (google/cf/quad9/adguard) → остальные по
    # алфавиту → российские в конце (xbox/comss/yandex/geohide/msk-ix/нсди)
    all_names.sort(key=_dns_name_sort_key)

    doh_by_name: dict[str, list[str]] = {}
    udp_by_name: dict[str, list[str]] = {}
    dot_by_name: dict[str, list[str]] = {}
    doh_ports: dict[str, list[int]] = {}
    udp_ports: dict[str, list[int]] = {}
    dot_ports: dict[str, list[int]] = {}
    for a, n, p in doh_servers:
        doh_by_name.setdefault(n, []).append(a)
        doh_ports.setdefault(n, []).append(p)
    for a, n, p in udp_servers:
        udp_by_name.setdefault(n, []).append(a)
        udp_ports.setdefault(n, []).append(p)
    for a, n, p in dot_servers:
        dot_by_name.setdefault(n, []).append(a)
        dot_ports.setdefault(n, []).append(p)

    # ── Заголовок ─────────────────────────────────────────────────────────────
    console.print(
        f"\n[bold]Проверка доступности DNS-серверов[/bold]  "
        f"[dim]DoH: {len(doh_servers)} | DoT: {len(dot_servers)} | UDP: {len(udp_servers)}"
        f" | Запрещённых: {len(forbidden)} | Доверенных: {len(allowed)}"
        f" | timeout: {timeout}s[/dim]"
    )
    console.print()

    # ── Таблицы эндпоинтов (DoH, DoT, UDP) ───────────────────────────────────
    from rich.table import Table as _Table

    if doh_servers:
        doh_table = _Table(title="[bold magenta]DoH эндпоинты[/bold magenta]",
                           show_header=True, header_style="bold magenta",
                           border_style="dim", box=None, pad_edge=False)
        doh_table.add_column("Провайдер", style="bold cyan", no_wrap=True, min_width=16)
        doh_table.add_column("DoH URL", style="dim", no_wrap=False)
        for name in all_names:
            urls = doh_by_name.get(name, [])
            if not urls:
                continue
            dports = doh_ports.get(name, [])
            doh_disp = [_doh_url_with_port(u, p) if p != 443 else u
                        for u, p in zip(urls, dports)]
            doh_str = "\n".join(f"{u} [dim]#{i+1}[/dim]" if len(doh_disp) > 1 else u
                                for i, u in enumerate(doh_disp))
            doh_table.add_row(name, doh_str)
        console.print(doh_table)
        console.print()

    if dot_servers:
        dot_table = _Table(title="[bold magenta]DoT эндпоинты[/bold magenta]",
                           show_header=True, header_style="bold magenta",
                           border_style="dim", box=None, pad_edge=False)
        dot_table.add_column("Провайдер", style="bold cyan", no_wrap=True, min_width=16)
        dot_table.add_column("DoT эндпоинты", style="dim", no_wrap=False)
        for name in all_names:
            eps = dot_by_name.get(name, [])
            if not eps:
                continue
            eports = dot_ports.get(name, [])
            dot_disp = [f"{e}:{p}" if p != 853 else e
                        for e, p in zip(eps, eports)]
            dot_str = ", ".join(f"{e} [dim]#{i+1}[/dim]" if len(dot_disp) > 1 else e
                                for i, e in enumerate(dot_disp))
            dot_table.add_row(name, dot_str)
        console.print(dot_table)
        console.print()

    if udp_servers:
        udp_table = _Table(title="[bold magenta]UDP эндпоинты[/bold magenta]",
                           show_header=True, header_style="bold magenta",
                           border_style="dim", box=None, pad_edge=False)
        udp_table.add_column("Провайдер", style="bold cyan", no_wrap=True, min_width=16)
        udp_table.add_column("UDP эндпоинты", style="dim", no_wrap=False)
        for name in all_names:
            ips = udp_by_name.get(name, [])
            if not ips:
                continue
            uports = udp_ports.get(name, [])
            udp_disp = [f"{ip}:{p}" if p != 53 else ip
                        for ip, p in zip(ips, uports)]
            udp_str = ", ".join(f"{ip} [dim]#{i+1}[/dim]" if len(udp_disp) > 1 else ip
                                for i, ip in enumerate(udp_disp))
            udp_table.add_row(name, udp_str)
        console.print(udp_table)
        console.print()

    # ── Домены проверки и дисклеймер ──────────────────────────────────────────
    console.print(
        f"[bold]Заблокированные домены для проверки:[/bold] {', '.join(forbidden)}\n"
        f"[bold]Незаблокированные домены для проверки:[/bold] {', '.join(allowed)}\n"
        "[bold yellow]ВНИМАНИЕ:[/bold yellow] Это независимая проверка и она не использует ваши настроенные DNS!"
    )
    if proxy_url and not socks_proxy:
        console.print(
            "[yellow]Прокси не SOCKS5 — UDP-пробы идут напрямую: "
            "через HTTP-прокси UDP-релей невозможен.[/yellow]"
        )

    # ── Счётчик прогресса ─────────────────────────────────────────────────────
    total_probes  = len(doh_servers) + len(udp_servers) + len(dot_servers)
    done_count    = 0
    progress_lock = asyncio.Lock()

    def _redraw_progress():
        import sys
        bar = f"  Проверка серверов... {done_count}/{total_probes}"
        sys.stderr.write(f"\r{bar}   ")
        sys.stderr.flush()

    async def _tick():
        nonlocal done_count
        async with progress_lock:
            done_count += 1
            _redraw_progress()

    # ── данные замеров ────────────────────────────────────────────────────────
    # raw[(kind, addr, name)][domain] = elapsed_ms or None (тайминг/успешность)
    raw: dict[tuple, dict[str, Optional[int]]] = {}
    fail_reasons: dict[tuple, str] = {}   # (kind, addr, name) -> ярлык причины фейла
    # Ответы по доменам: (kind, addr, name, domain) -> list[ip] | "NXDOMAIN" |
    # "PARSE_ERR" | None (таймаут/нет ответа). Нужны для сравнения подмены.
    udp_answers: dict[tuple, object] = {}
    doh_answers: dict[tuple, object] = {}
    dot_answers: dict[tuple, object] = {}

    # ── UDP probe: фаза A (доверенные) → фаза B (запрещённые, если жив) ──────
    async def _probe_udp(addr: str, name: str, port: int = 53) -> None:
        key = ("udp", addr, name)
        loop = asyncio.get_running_loop()
        udp_sem = asyncio.Semaphore(getattr(config, "DNS_UDP_CONCURRENCY", 15))

        async def _wait(domain: str):
            async with udp_sem:
                if socks_proxy:
                    elapsed_ms, parsed = await _Socks5UdpRelay(*socks_proxy).query(
                        addr, domain, timeout, port
                    )
                    ok = isinstance(parsed, list)   # "успех" — только с реальными IP
                    return domain, (elapsed_ms if ok else None), parsed
                q = _build_dns_query(domain)
                tx_id = q[:2]
                fut = loop.create_future()
                transport = None
                t0 = time.perf_counter()
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: _SingleQueryProto(fut), remote_addr=(addr, port)
                    )
                    transport.sendto(q)
                    data, t_recv = await asyncio.wait_for(fut, timeout=timeout)
                    elapsed_ms = round((t_recv - t0) * 1000, 1)
                    parsed = _parse_dns_response(data, tx_id)
                    ok = isinstance(parsed, list)   # "успех" — только с реальными IP
                    return domain, (elapsed_ms if ok else None), parsed
                except Exception as e:
                    logger.debug("UDP probe error for %s: %s", domain, e, exc_info=True)
                    return domain, None, None
                finally:
                    if transport:
                        transport.close()

        # Фаза A: доступность по доверенным доменам
        pairs_a = await asyncio.gather(*[_wait(d) for d in allowed])
        available = any(e is not None for _, e, _ in pairs_a)
        res = {d: e for d, e, _ in pairs_a}
        for d, _e, parsed in pairs_a:
            udp_answers[("udp", addr, name, d)] = parsed
        # Фаза B: только живому серверу — запрещённые домены на проверку подмены
        if available and forbidden:
            pairs_b = await asyncio.gather(*[_wait(d) for d in forbidden])
            res.update((d, e) for d, e, _ in pairs_b)
            for d, _e, parsed in pairs_b:
                udp_answers[("udp", addr, name, d)] = parsed
        raw[key] = res
        await _tick()

    # ── DoH JSON probe (не вызывается, оставлен для совместимости) ───────────
    async def _probe_doh_json(addr: str, name: str) -> None:
        key = ("doh_json", addr, name)
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(getattr(config, "DNS_DOH_CONCURRENCY", 20))

        async def _one(domain: str, client: httpx.AsyncClient):
            async with doh_sem:
                t0 = time.perf_counter()
                try:
                    resp = await client.get(addr, params={"name": domain, "type": "A"})
                    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                    if resp.status_code != 200:
                        return domain, None, None
                    data = resp.json()
                    if data.get("Status") == 3:
                        return domain, None, "NXDOMAIN"
                    ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                    return domain, (elapsed_ms if ips else None), (ips if ips else None)
                except Exception as e:
                    logger.debug("DoH JSON probe error for %s: %s", domain, e, exc_info=True)
                    return domain, None, None

        try:
            async with httpx.AsyncClient(
                timeout=cli_timeout,
                headers={"Accept": "application/dns-json", "User-Agent": config.USER_AGENT},
                proxy=proxy_url, trust_env=False,
            ) as client:
                try:
                    warmup_q = forbidden[0] if forbidden else "google.com"
                    await client.get(addr, params={"name": warmup_q, "type": "A"})
                except Exception as e:
                    logger.debug("DoH JSON warmup error: %s", e)
                pairs = await asyncio.gather(*[_one(d, client) for d in forbidden])
        except Exception as e:
            logger.debug("DoH JSON client error: %s", e, exc_info=True)
            pairs = [(d, None, None) for d in forbidden]
        raw[key] = {d: e for d, e, _ in pairs}
        for d, _e, parsed in pairs:
            doh_answers[("doh_json", addr, name, d)] = parsed
        await _tick()

    # ── DoH Wire probe: эталон "правды" по запрещённым доменам ───────────────
    # Один клиент на сервер, один TLS-коннект, боевые запросы последовательно
    # (иначе каждый открывает своё соединение и платит +300мс ТСПУ).
    async def _probe_doh_wire(addr: str, name: str, port: int = 443) -> None:
        key = ("doh_wire", addr, name)
        orig_addr = addr   # адрес до пининга — по нему храню ответы (совпадает с doh_by_name)
        try:
            # Нестандартный порт — вставляем в URL до пининга
            if port != 443:
                addr = _doh_url_with_port(addr, port)
            # Привязка к IP выбранного семейства: коннект по A-/AAAA-записи,
            # SNI и Host — от имени сервера
            addr, ehost = await pin_host(addr)
        except Exception as err:
            logger.debug("DoH pin_host error for %s: %s", addr, err)
            fail_reasons.setdefault(key, "[yellow]DNS FAIL[/yellow]")
            raw[key] = dict.fromkeys(forbidden)
            for d in forbidden:
                doh_answers[("doh_wire", orig_addr, name, d)] = None
            await _tick()
            return

        ehost_headers = {"Host": ehost} if ehost else {}
        ehost_ext = {"sni_hostname": ehost} if ehost else None
        cli_timeout = httpx.Timeout(timeout, connect=timeout, pool=2.0)
        doh_sem = asyncio.Semaphore(getattr(config, "DNS_DOH_CONCURRENCY", 20))
        single_conn = httpx.Limits(max_connections=1, max_keepalive_connections=1)
        async def _do_probe() -> list:
            conn_state = {"stage": "init"}

            async def _trace_hook(event_name: str, info):
                if event_name == "connection.connect_tcp.started":
                    conn_state["stage"] = "tcp_connect"
                elif event_name == "connection.connect_tcp.complete":
                    conn_state["stage"] = "tcp_connected"
                elif event_name == "connection.start_tls.started":
                    conn_state["stage"] = "tls_handshake"
                elif event_name == "connection.start_tls.complete":
                    conn_state["stage"] = "tls_connected"

            trace_ext = {**ehost_ext, "trace": _trace_hook} if ehost_ext else {"trace": _trace_hook}

            async def _one(domain: str, client: httpx.AsyncClient):
                async with doh_sem:
                    query = _build_dns_query(domain)
                    tx_id = query[:2]
                    last_err: Optional[Exception] = None
                    for attempt in range(2):
                        if attempt:
                            await asyncio.sleep(0.3 + os.urandom(1)[0] / 255 * 0.7)
                        try:
                            t0 = time.perf_counter()
                            resp = await client.post(
                                addr, content=query,
                                headers={
                                    "Content-Type": "application/dns-message",
                                    "Accept":       "application/dns-message",
                                    "User-Agent":   config.USER_AGENT,
                                    **ehost_headers,
                                },
                                extensions=trace_ext,
                            )
                            if resp.status_code != 200:
                                dns_b64 = base64.urlsafe_b64encode(query).rstrip(b'=').decode()
                                t0 = time.perf_counter()
                                resp = await client.get(
                                    addr, params={"dns": dns_b64},
                                    headers={"Accept": "application/dns-message",
                                             "User-Agent": config.USER_AGENT,
                                             **ehost_headers},
                                    extensions=trace_ext,
                                )
                            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                            if resp.status_code != 200:
                                return domain, None, None
                            result = _parse_dns_response(resp.content, tx_id)
                            ok = isinstance(result, list)
                            return domain, (elapsed_ms if ok else None), result
                        except Exception as err:
                            last_err = err
                    if last_err is not None:
                        _record_fail(last_err)
                    return domain, None, None

            try:
                async with httpx.AsyncClient(
                    timeout=cli_timeout,
                    proxy=proxy_url, trust_env=False, http2=True,
                    limits=single_conn,
                ) as client:

                    def _record_fail(err: Exception) -> None:
                        if key in fail_reasons:
                            return
                        stage = conn_state.get("stage", "init")
                        if isinstance(err, (httpx.ReadTimeout, httpx.ReadError,
                                            httpx.RemoteProtocolError, httpx.WriteTimeout,
                                            httpx.PoolTimeout)):
                            label, _, _ = classify_read_error(err, 0, stage=stage)
                        else:
                            label, _, _ = classify_connect_error(err, 0, stage=stage)
                        fail_reasons[key] = label

                    try:
                        warmup = _build_dns_query(forbidden[0] if forbidden else "google.com")
                        await client.post(
                            addr, content=warmup,
                            headers={"Content-Type": "application/dns-message",
                                     "Accept": "application/dns-message",
                                     "User-Agent": config.USER_AGENT,
                                     **ehost_headers},
                            extensions=trace_ext,
                        )
                    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.TimeoutException) as err:
                        _record_fail(err)
                        return [(d, None, None) for d in forbidden]
                    except Exception as e:
                        logger.debug("DoH wire warmup non-critical error: %s", e)

                    # Боевые запросы ПОСЛЕДОВАТЕЛЬНО (фикс плоских 300мс ТСПУ)
                    results = []
                    for d in forbidden:
                        results.append(await _one(d, client))
                    return results
            except Exception as err:
                if isinstance(err, (TimeoutError, asyncio.TimeoutError)):
                    fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
                else:
                    fail_reasons.setdefault(
                        key, f"[red]UNKNOWN[/red] [dim]{type(err).__name__}[/dim]"
                    )
                return [(d, None, None) for d in forbidden]

        try:
            pairs = await asyncio.wait_for(_do_probe(), timeout=timeout * 2 + 3.0)
            raw[key] = {d: e for d, e, _ in pairs}
            for d, _e, parsed in pairs:
                doh_answers[("doh_wire", orig_addr, name, d)] = parsed
        except (asyncio.TimeoutError, Exception):
            fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
            raw[key] = dict.fromkeys(forbidden)
            for d in forbidden:
                doh_answers[("doh_wire", orig_addr, name, d)] = None
        finally:
            await _tick()

    # ── DoT probe (RFC 7858): TLS:853, wire-запросы с 2-байт length-prefix ───
    # Один TLS-коннект на сервер, запросы последовательно (как DoH Wire).
    # httpx DoT не умеет — сырой asyncio. Прокси не поддерживается (как UDP).

    async def _probe_dot(addr: str, name: str, port: int = 853) -> None:
        key = ("dot", addr, name)
        try:
            host, ep_port = _split_dot_endpoint(addr)
            # 4-й элемент конфига переопределяет порт; иначе — порт из адреса ('host:port')
            if port == 853:
                port = ep_port
            # Коннект по IP выбранного семейства (config.IP_VERSION),
            # SNI/сертификат — по имени сервера (для IP-литерала — IP-SAN)
            if is_ip_literal(host):
                connect_host = server_hostname = host
            else:
                ip = await get_resolved_ip(host)
                connect_host, server_hostname = (ip or host), host
        except Exception as err:
            logger.debug("DoT resolve error for %s: %s", addr, err)
            fail_reasons.setdefault(key, "[yellow]DNS FAIL[/yellow]")
            raw[key] = dict.fromkeys(forbidden)
            for d in forbidden:
                dot_answers[("dot", addr, name, d)] = None
            await _tick()
            return
        ctx = create_dot_ssl_context()
        conn_state = {"stage": "init"}

        def _record_fail(err: Exception) -> None:
            if key in fail_reasons:
                return
            stage = conn_state.get("stage", "init")
            label, _, _ = classify_connect_error(err, 0, stage=stage)
            fail_reasons[key] = label
        async def _one(domain: str, reader, writer) -> tuple:
            q = _build_dns_query(domain)
            tx_id = q[:2]
            try:
                t0 = time.perf_counter()
                writer.write(struct.pack("!H", len(q)) + q)
                await writer.drain()
                (n,) = struct.unpack("!H", await asyncio.wait_for(
                    reader.readexactly(2), timeout=timeout))
                data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                parsed = _parse_dns_response(data, tx_id)
                ok = isinstance(parsed, list)
                return domain, (elapsed_ms if ok else None), parsed
            except Exception as e:
                logger.debug("DoT query error for %s: %s", domain, e, exc_info=True)
                return domain, None, None

        async def _do_probe() -> list:
            try:
                conn_state["stage"] = "tcp_connect"
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(connect_host, port, ssl=ctx,
                                            server_hostname=server_hostname),
                    timeout=timeout,
                )
                conn_state["stage"] = "tls_connected"
            except Exception as err:
                if isinstance(err, ssl.SSLError):
                    conn_state["stage"] = "tls_handshake"
                _record_fail(err)
                return [(d, None, None) for d in forbidden]
            try:
                # warmup: убедиться, что сервер реально отвечает по TLS
                q = _build_dns_query(forbidden[0] if forbidden else "google.com")
                writer.write(struct.pack("!H", len(q)) + q)
                await writer.drain()
                (n,) = struct.unpack("!H", await asyncio.wait_for(
                    reader.readexactly(2), timeout=timeout))
                await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
                # Боевые запросы ПОСЛЕДОВАТЕЛЬНО (один поток, как DoH Wire)
                results = []
                for d in forbidden:
                    results.append(await _one(d, reader, writer))
                return results
            except Exception as err:
                _record_fail(err)
                return [(d, None, None) for d in forbidden]
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug("DoT writer close error: %s", e)

        try:
            pairs = await asyncio.wait_for(_do_probe(), timeout=timeout * 2 + 3.0)
            raw[key] = {d: e for d, e, _ in pairs}
            for d, _e, parsed in pairs:
                dot_answers[("dot", addr, name, d)] = parsed
        except (asyncio.TimeoutError, Exception):
            fail_reasons.setdefault(key, "[red]TIMEOUT[/red]")
            raw[key] = dict.fromkeys(forbidden)
            for d in forbidden:
                dot_answers[("dot", addr, name, d)] = None
        finally:
            await _tick()

    # ── Запускаем: Wire + DoT + UDP ──────────────────────────────────────────
    probe_gate = asyncio.Semaphore(getattr(config, "DNS_PROBE_CONCURRENCY", 20))
    # ── Выходной резолвер: A whoami.akamai.net ────────────────────────────────
    egress: dict[tuple, Optional[str]] = {}

    async def _probe_egress(addr: str, name: str, port: int = 53) -> None:
        key = ("egress", addr, name)
        if socks_proxy:
            _elapsed, parsed = await _Socks5UdpRelay(*socks_proxy).query(
                addr, "whoami.akamai.net", timeout, port
            )
            egress[key] = parsed[0] if isinstance(parsed, list) and parsed else None
            return
        loop = asyncio.get_running_loop()
        result = None
        # Повторный запрос при пустом ответе: одиночная проба whoami
        # теряется (таймаут/пустой ответ) — один ретрай убирает «выход н/д»
        for attempt in range(2):
            fut: asyncio.Future = loop.create_future()
            transport = None
            try:
                q = _build_dns_query("whoami.akamai.net")
                transport, _ = await loop.create_datagram_endpoint(
                    lambda fut=fut: _SingleQueryProto(fut), remote_addr=(addr, port)
                )
                transport.sendto(q)
                data, _t = await asyncio.wait_for(fut, timeout=timeout)
                parsed = _parse_dns_response(data, q[:2])
                result = parsed[0] if isinstance(parsed, list) and parsed else None
            except Exception as e:
                logger.debug("probe_egress error for %s: %s", addr, e, exc_info=True)
                result = None
            finally:
                if transport:
                    transport.close()
            if result:
                break
            if attempt == 0:
                await asyncio.sleep(0.2)   # не попасть в тот же слот таймаута
        egress[key] = result

    async def _probe_udp_gated(addr, name, port):
        async with probe_gate:
            await _probe_udp(addr, name, port)

    async def _probe_doh_wire_gated(addr, name, port):
        async with probe_gate:
            await _probe_doh_wire(addr, name, port)
    async def _probe_dot_gated(addr, name, port):
        async with probe_gate:
            await _probe_dot(addr, name, port)

    egress_sem = asyncio.Semaphore(getattr(config, "DNS_EGRESS_CONCURRENCY", 10))

    async def _probe_egress_gated(addr, name, port):
        async with egress_sem:
            await _probe_egress(addr, name, port)

    # ── Имена организаций выходных IP (Team Cymru через DoH, RFC 8484) ────────
    # Эндпоинты в config (CYMRU_DOH_SERVERS): dns.google → cloudflare → yandex.
    _CYMRU_DOH = tuple(getattr(config, "CYMRU_DOH_SERVERS",
                               ("https://dns.google/dns-query",
                                "https://cloudflare-dns.com/dns-query",
                                "https://common.dot.dns.yandex.net/dns-query")))

    async def _resolve_asn_names() -> dict[str, str]:
        return await resolve_asn_names(list(egress.values()), proxy_url=getattr(config, "PROXY_URL", None))

    _redraw_progress()
    if udp_servers:
        await asyncio.gather(
            *[_probe_udp_gated(a, n, p) for a, n, p in udp_servers]
          + [_probe_egress_gated(a, n, p) for a, n, p in udp_servers],
            return_exceptions=True
        )
    # Орг-имена egress резолвим в фоне — параллельно с DoH/DoT-пробами,
    # чтобы не ждать их в конце (раньше это давало +секунды после теста)
    org_task = asyncio.create_task(_resolve_asn_names()) if udp_servers else None

    if wire_servers:
        await asyncio.gather(*[_probe_doh_wire_gated(a, n, p) for a, n, p in wire_servers], return_exceptions=True)
    if dot_servers:
        await asyncio.gather(*[_probe_dot_gated(a, n, p) for a, n, p in dot_servers], return_exceptions=True)

    import sys
    sys.stderr.write(f"\r  Проверено серверов: {done_count}/{total_probes}          \n")
    sys.stderr.flush()

    org_names = await org_task if org_task is not None else {}

    return render_dns_availability_results(
        allowed=allowed,
        forbidden=forbidden,
        raw=raw,
        fail_reasons=fail_reasons,
        doh_answers=doh_answers,
        udp_answers=udp_answers,
        dot_answers=dot_answers,
        egress=egress,
        org_names=org_names,
        all_names=all_names,
        doh_servers=doh_servers,
        udp_servers=udp_servers,
        dot_servers=dot_servers,
        doh_by_name=doh_by_name,
        udp_by_name=udp_by_name,
        dot_by_name=dot_by_name,
    )
