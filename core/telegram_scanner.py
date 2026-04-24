"""
telegram_scanner.py — Тест 5: Проверка замедления/блокировки Telegram.
"""
import asyncio
import ssl
import time
from typing import List, Tuple, Optional

import httpx
from rich.console import Console
from rich.live import Live
from rich.table import Table
from cli.console import console as main_console
from utils import config

live_console = Console(record=False)

# ─── Константы ───────────────────────────────────────────────────────────────
MEDIA_URL     = "https://telegram.org/img/Telegram200million.png"
MEDIA_HOST    = "telegram.org"
MEDIA_PORT    = 443
MEDIA_SIZE_MB = 30.97
MEDIA_SIZE_B  = int(MEDIA_SIZE_MB * 1024 * 1024)

TELEGRAM_DC_IPS: List[Tuple[str, str]] = [
    ("149.154.175.53",  "DC1"),
    ("149.154.167.51",  "DC2"),
    ("149.154.175.100", "DC3"),
    ("149.154.167.91",  "DC4"),
    ("91.108.56.130",   "DC5"),
]
TELEGRAM_DC_PORT = 443

UPLOAD_TEST_IP   = "149.154.167.220"
UPLOAD_TEST_PORT = 443
UPLOAD_SIZE_MB   = 10
UPLOAD_SIZE_B    = UPLOAD_SIZE_MB * 1024 * 1024

STALL_TIMEOUT   = 10.0   # сек без данных → прерываем
TOTAL_TIMEOUT   = 60.0   # общий таймаут
DC_PING_TIMEOUT = 5.0

_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# ─── Форматирование ──────────────────────────────────────────────────────────
def _fmt_speed(bps: float) -> str:
    if bps >= 1024 * 1024:
        return f"{bps / (1024*1024):>6.2f} МБ/с"
    if bps >= 1024:
        return f"{bps / 1024:>6.1f} КБ/с"
    return f"{bps:>6.0f} Б/с"

def _fmt_size(b: int) -> str:
    if b >= 1024 * 1024:
        return f"{b / (1024*1024):.2f} МБ"
    if b >= 1024:
        return f"{b / 1024:.1f} КБ"
    return f"{b} Б"

# ─── Rich LiveDisplay ────────────────────────────────────────────────────────
class LiveDisplay:
    """Управляет обновлением 3 строк состояния через rich.live."""
    def __init__(self):
        self._lock = asyncio.Lock()
        self.labels = ["Скачивание", "Загрузка  ", "Датацентры"]
        self.statuses = ["[dim]ожидание...[/dim]"] * 3

        self.live = Live(self._build_table(), console=live_console, refresh_per_second=10, transient=True)

    def _build_table(self) -> Table:
        """Собирает невидимую сетку (grid) для выравнивания текста."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column()
        for label, status in zip(self.labels, self.statuses):
            grid.add_row(f"  {label}:", status)
        return grid

    async def start(self):
        self.live.start()

    async def update(self, row: int, text: str):
        async with self._lock:
            self.statuses[row] = text
            self.live.update(self._build_table())

    async def finish(self):
        self.live.stop()
        main_console.print(self._build_table())

# ─── TCP-пинг DC ─────────────────────────────────────────────────────────────
async def _tcp_ping(ip: str, port: int) -> Tuple[bool, Optional[float]]:
    """Проверяет доступность DC через сырой TCP-хэндшейк (L4)."""
    t0 = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=DC_PING_TIMEOUT
        )
        rtt = time.monotonic() - t0
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, rtt
    except Exception:
        return False, None

async def _check_dc(display: LiveDisplay) -> List[dict]:
    spin  = 0
    results = []
    total = len(TELEGRAM_DC_IPS)
    lock  = asyncio.Lock()

    async def _one(ip, label):
        nonlocal spin
        reachable, rtt = await _tcp_ping(ip, TELEGRAM_DC_PORT)

        async with lock:
            results.append({"ip": ip, "label": label, "reachable": reachable, "rtt": rtt})
            spin = (spin + 1) % len(_SPIN)
            ok   = sum(1 for x in results if x["reachable"])
            await display.update(2, f"[dim]{_SPIN[spin]} проверяем {len(results)}/{total}  доступно: {ok}[/dim]")

    await asyncio.gather(*[_one(ip, lbl) for ip, lbl in TELEGRAM_DC_IPS])

    ok    = sum(1 for d in results if d["reachable"])
    parts = []
    for d in sorted(results, key=lambda x: x["label"]):
        rtt_s = f" {d['rtt']*1000:.0f}мс" if d.get("rtt") else ""
        if d["reachable"]:
            parts.append(f"[green]{d['label']}[/green][dim]{rtt_s}[/dim]")
        else:
            parts.append(f"[red]{d['label']}✗[/red]")

    if ok == total:
        st = f"[green]ОК {ok}/{total}[/green]"
    elif ok == 0:
        st = f"[red]НЕДОСТУПНЫ 0/{total}[/red]"
    else:
        st = f"[yellow]{ok}/{total}[/yellow]"

    await display.update(2, f"{st}  {'  '.join(parts)}")
    return results

# ─── Upload ──────────────────────────────────────────────────────────────────
async def _run_upload(display: LiveDisplay) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    proxy_url = getattr(config, "PROXY_URL", None)

    sent_ref = [0]
    peak_ref = [0.0]
    t0 = time.monotonic()
    last_data_time = time.monotonic()
    last_nonzero_sec = 0
    stop_ev = asyncio.Event()

    async def _body():
        chunk = b"\x00" * 16384
        while sent_ref[0] < UPLOAD_SIZE_B:
            if stop_ev.is_set(): break
            yield chunk
            sent_ref[0] += len(chunk)
            # Небольшой yield в event loop, чтобы не блокировать другие задачи
            await asyncio.sleep(0)

    async def _watcher():
        nonlocal last_data_time, last_nonzero_sec
        prev = 0
        while not stop_ev.is_set():
            await asyncio.sleep(0.5)
            now = time.monotonic()
            elapsed = now - t0

            if elapsed >= TOTAL_TIMEOUT:
                stop_ev.set()
                return

            sent = sent_ref[0]
            delta = sent - prev

            if delta > 0:
                last_data_time = now
                last_nonzero_sec = int(elapsed)

            if now - last_data_time >= STALL_TIMEOUT:
                stop_ev.set()
                return

            cur_bps = delta / 0.5
            peak_ref[0] = max(peak_ref[0], cur_bps)
            avg_bps = sent / elapsed if elapsed > 0 else 0

            prev = sent

            color = "green" if delta > 0 else "red"
            await display.update(1,
                f"[dim]В ПРОЦЕССЕ[/dim]  тек [{color}]{_fmt_speed(cur_bps)}[/{color}]  "
                f"ср. [cyan]{_fmt_speed(avg_bps)}[/cyan]  ({_fmt_size(sent):>8} из {UPLOAD_SIZE_MB}МБ)  ⏱ {elapsed:>2.0f}с"
            )

    async def _do_post():
        try:
            async with httpx.AsyncClient(verify=ctx, proxy=proxy_url, trust_env=False, timeout=TOTAL_TIMEOUT+5) as client:
                await client.post(f"https://{UPLOAD_TEST_IP}:{UPLOAD_TEST_PORT}/upload", content=_body())
        except Exception:
            pass

    watcher_task = asyncio.create_task(_watcher())
    post_task = asyncio.create_task(_do_post())

    # Ждем завершения
    done, pending = await asyncio.wait(
        [post_task, watcher_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    stop_ev.set()
    for t in pending: t.cancel()

    duration = time.monotonic() - t0
    sent = sent_ref[0]
    avg = sent / duration if duration > 0 else 0
    peak = max(peak_ref[0], avg)
    fully = sent >= UPLOAD_SIZE_B * 0.98

    if sent == 0:
        status, st_text, color = "blocked", "НЕДОСТУПНО ", "red"
    elif fully:
        status, st_text, color = "ok", "ОК        ", "green"
    elif (time.monotonic() - last_data_time) >= STALL_TIMEOUT:
        status, st_text, color = "stalled", "ОБРЫВ     ", "yellow"
    else:
        status, st_text, color = "slow", "ЗАМЕДЛЕНИЕ", "yellow"

    extra = f", обрыв после {last_nonzero_sec}с" if status == "stalled" else ""
    await display.update(1, f"[{color}]{st_text}[/{color}]  пик [cyan]{_fmt_speed(peak)}[/cyan]  ср. {_fmt_speed(avg)}  ({_fmt_size(sent)} за {duration:.0f}с{extra})")

    return {
        "status": status,
        "avg_bps": avg, "bps": avg,
        "peak_bps": peak,
        "bytes_total": sent, "sent": sent,
        "duration": duration, "elapsed": duration,
        "drop_at_sec": last_nonzero_sec if status == "stalled" else None
    }

# ─── Download ────────────────────────────────────────────────────────────────
async def _run_download(display: LiveDisplay) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    proxy_url = getattr(config, "PROXY_URL", None)

    total_bytes = 0
    tick_bytes = 0
    t_start = None
    last_data_time = time.monotonic()
    last_nonzero_sec = 0
    peak_bps = 0
    stop_event = asyncio.Event()

    async def _ticker():
        nonlocal tick_bytes, total_bytes, last_data_time, last_nonzero_sec, peak_bps
        sec = 0
        while not stop_event.is_set():
            await asyncio.sleep(1.0)
            if t_start is None: continue
            sec += 1

            bps = tick_bytes
            tick_bytes = 0
            peak_bps = max(peak_bps, bps)
            elapsed = time.monotonic() - t_start

            if bps > 0:
                last_data_time = time.monotonic()
                last_nonzero_sec = sec

            avg = total_bytes / elapsed if elapsed > 0 else 0
            color = "green" if bps > 0 else "red"

            await display.update(0,
                f"[dim]В ПРОЦЕССЕ[/dim]  тек [{color}]{_fmt_speed(bps)}[/{color}]  "
                f"ср. [cyan]{_fmt_speed(avg)}[/cyan]  ({_fmt_size(total_bytes):>8} из {MEDIA_SIZE_MB}МБ)  ⏱ {sec:>2}с"
            )

            if time.monotonic() - last_data_time >= STALL_TIMEOUT:
                stop_event.set()
            if sec >= TOTAL_TIMEOUT:
                stop_event.set()

    async def _reader():
        nonlocal total_bytes, tick_bytes, t_start
        try:
            async with httpx.AsyncClient(verify=ctx, proxy=proxy_url, trust_env=False, timeout=TOTAL_TIMEOUT+5) as client:
                req = client.build_request("GET", MEDIA_URL)
                response = await client.send(req, stream=True)

                t_start = time.monotonic()
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    if stop_event.is_set():
                        break
                    chunk_len = len(chunk)
                    total_bytes += chunk_len
                    tick_bytes += chunk_len

                await response.aclose()
        except Exception:
            pass

    ticker_t = asyncio.create_task(_ticker())
    reader_t = asyncio.create_task(_reader())

    await asyncio.wait([ticker_t, reader_t], return_when=asyncio.FIRST_COMPLETED)

    stop_event.set()
    ticker_t.cancel()
    reader_t.cancel()

    duration = (time.monotonic() - t_start) if t_start else 0
    fully = total_bytes >= MEDIA_SIZE_B * 0.98

    # Логика определения вердикта
    if total_bytes == 0:
        status, st_text, color = "blocked", "НЕДОСТУПНО ", "red"
    elif fully:
        status, st_text, color = "ok", "ОК        ", "green"
    elif (time.monotonic() - last_data_time) >= STALL_TIMEOUT:
        status, st_text, color = "stalled", "ОБРЫВ     ", "yellow"
    else:
        status, st_text, color = "slow", "ЗАМЕДЛЕНИЕ", "yellow"

    avg_final = total_bytes / (last_nonzero_sec if status == "stalled" else (duration or 1))
    extra = f", обрыв после {last_nonzero_sec}с" if status == "stalled" else ""
    await display.update(0, f"[{color}]{st_text}[/{color}]  пик [cyan]{_fmt_speed(peak_bps)}[/cyan]  ср. {_fmt_speed(avg_final)}  ({_fmt_size(total_bytes)} за {duration:.0f}с{extra})")

    return {
        "status": status,
        "avg_bps": avg_final, "bps": avg_final,
        "peak_bps": peak_bps,
        "bytes_total": total_bytes, "sent": total_bytes,
        "duration": duration, "elapsed": duration,
        "drop_at_sec": last_nonzero_sec if status == "stalled" else None
    }

async def run_telegram_test(semaphore: asyncio.Semaphore) -> dict:
    display = LiveDisplay()
    await display.start()

    dl_res, ul_res, dc_res = await asyncio.gather(
        _run_download(display),
        _run_upload(display),
        _check_dc(display),
        return_exceptions=True
    )

    await display.finish()

    _empty_stats = {"status": "error", "avg_bps": 0, "bps": 0, "peak_bps": 0, "bytes_total": 0, "sent": 0, "duration": 0, "elapsed": 0, "drop_at_sec": None}

    if isinstance(dl_res, Exception): dl_res = _empty_stats
    if isinstance(ul_res, Exception): ul_res = _empty_stats
    if isinstance(dc_res, Exception): dc_res = []

    dl_st = dl_res.get("status")
    ul_st = ul_res.get("status")
    dc_reachable = sum(1 for d in dc_res if isinstance(d, dict) and d.get("reachable"))
    dc_total = len(dc_res)

    if (dl_st == "blocked" or ul_st == "blocked") and dc_reachable == 0:
        verdict = "blocked"
    elif dl_st in ("stalled", "slow") or ul_st in ("stalled", "slow"):
        verdict = "slow"
    elif dc_reachable < dc_total and dc_reachable > 0:
        verdict = "partial"
    elif dl_st == "ok" and ul_st == "ok":
        verdict = "ok"
    else:
        verdict = "error"

    return {
        "verdict":      verdict,
        "download":     dl_res,
        "upload":       ul_res,
        "dc_results":   dc_res,
        "dc_reachable": dc_reachable,
        "dc_total":     dc_total,
    }