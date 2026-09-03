import asyncio
import random
import string
import time
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)
import httpx
from utils import config
from utils.network import format_ip_for_url, create_insecure_dpi_ssl_context
from utils.error_classifier import classify_connect_error, classify_read_error
# Ленивая генерация пула случайных символов для X-Pad (не при импорте модуля).
_RANDOM_POOL: Optional[str] = None


def get_random_pool() -> str:
    global _RANDOM_POOL
    if _RANDOM_POOL is None:
        size = getattr(config, "FAT_RANDOM_POOL_SIZE", 100_000)
        _RANDOM_POOL = "".join(random.choices(string.ascii_letters + string.digits, k=size))
    return _RANDOM_POOL


def __getattr__(name: str):
    if name == "RANDOM_POOL":
        return get_random_pool()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

async def _fat_probe_keepalive(
    client: httpx.AsyncClient, ip: str, port: int, sni: Optional[str],
    hint_rtt: Optional[float] = None,
) -> Tuple[str, str, str, Optional[float]]:
    """
    hint_rtt: если передан известный RTT (сек) — пропускаем фазу измерения
    и сразу используем его для dynamic_timeout. Ускоряет перебор SNI.
    """
    scheme = "http" if port == 80 else "https"
    url = f"{scheme}://{format_ip_for_url(ip)}:{port}/"

    base_headers = {
        "User-Agent": config.USER_AGENT,
        "Connection": "keep-alive"
    }
    if sni:
        base_headers["Host"] = sni

    connection_state = {"stage": "init"}

    async def trace_hook(event_name, info):
        # TCP (SYN)
        if event_name == "connection.connect_tcp.started":
            connection_state["stage"] = "tcp_connect"
        elif event_name == "connection.connect_tcp.complete":
            connection_state["stage"] = "tcp_connected"
        # TLS Handshake
        elif event_name == "connection.start_tls.started":
            connection_state["stage"] = "tls_handshake"
        elif event_name == "connection.start_tls.complete":
            connection_state["stage"] = "tls_connected"
        # Отправка/чтение данных
        elif event_name.startswith("http11.send_request"):
            connection_state["stage"] = "sending_data"
        elif event_name.startswith("http11.receive_response"):
            connection_state["stage"] = "reading_data"

    alive_str = "[dim]—[/dim]"
    chunks_count = getattr(config, "FAT_CHUNKS_COUNT", 10)  # 10 × 4KB = 40KB
    chunk_size = getattr(config, "FAT_CHUNK_SIZE", 4000)
    # Детект-порог по TCP_BLOCK_MIN_KB: первый чанк, после которого суммарно
    # отправлено ≥ минимального порога блокировки (конфиг, а не магия "3")
    min_detect_chunk = max(1, int(getattr(config, "TCP_BLOCK_MIN_KB", 12) * 1024
                                  / max(chunk_size, 1)))

    rtt_measurements = []
    # Если RTT известен заранее — сразу выставляем dynamic_timeout
    if hint_rtt is not None:
        dyn_t = max(hint_rtt * 3.0, 1.5)
        dynamic_timeout = min(dyn_t, config.FAT_READ_TIMEOUT)
    else:
        dynamic_timeout = None

    extensions = {"trace": trace_hook}
    if sni and port != 80:
        extensions["sni_hostname"] = sni

    measured_rtt = hint_rtt

    for i in range(chunks_count):
        headers = base_headers.copy()
        # i=0 — чистый запрос без X-Pad: только проверяем что сервер живой.
        # i>=1 — добавляем мусор
        if i > 0:
            pool = get_random_pool()
            start_idx = random.randint(0, len(pool) - chunk_size - 1)
            headers["X-Pad"] = pool[start_idx:start_idx + chunk_size]

        timeout_read = dynamic_timeout if dynamic_timeout is not None else config.FAT_READ_TIMEOUT
        custom_timeout = httpx.Timeout(
            timeout_read,
            connect=config.FAT_CONNECT_TIMEOUT,
            pool=config.POOL_TIMEOUT
        )

        start_time = time.monotonic()

        try:
            await client.request(
                "HEAD", url, headers=headers,
                timeout=custom_timeout,
                extensions=extensions if extensions else None
            )

            elapsed = time.monotonic() - start_time

            if i == 0:
                alive_str = "[green]Да[/green]"
                if measured_rtt is None:
                    measured_rtt = elapsed

            # Измеряем RTT на первых 2 запросах только если hint не был передан
            if hint_rtt is None and i < 2:
                rtt_measurements.append(elapsed)
                if len(rtt_measurements) == 2:
                    base_rtt = max(rtt_measurements)
                    dyn_t = max(base_rtt * 3.0, 1.5)
                    dynamic_timeout = min(dyn_t, config.FAT_READ_TIMEOUT)

            await asyncio.sleep(getattr(config, "FAT_CHUNK_DELAY", 0.05))

        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            logger.debug("TCP16 connect error for %s (chunk %d): %s", ip, i, e)
            label, detail, _ = classify_connect_error(e, 0, stage=connection_state["stage"])
            if i == 0:
                return "[red]Нет[/red]", label, detail, measured_rtt
            if i < min_detect_chunk:  # вне детект-диапазона DPI — обычный обрыв
                return alive_str, "[red]TIMEOUT[/red]", detail, measured_rtt
            return alive_str, "[bold red]DETECTED[/bold red]", f"{detail} at {i*chunk_size//1024}KB", measured_rtt

        except (httpx.ReadTimeout, httpx.WriteTimeout) as e:
            logger.debug("TCP16 timeout for %s (chunk %d): %s", ip, i, e)
            err_type = "Read Timeout" if isinstance(e, httpx.ReadTimeout) else "Write Timeout"
            if i == 0:
                return "[green]Да[/green]", f"[red]{err_type.upper()}[/red]", err_type, measured_rtt
            if i < min_detect_chunk:  # вне детект-диапазона DPI
                return alive_str, "[red]TIMEOUT[/red]", err_type, measured_rtt
            return alive_str, "[bold red]DETECTED[/bold red]", f"{err_type} at {i*chunk_size//1024}KB", measured_rtt

        except Exception as e:
            # Для ReadError, WriteError, RemoteProtocolError и любых других
            logger.debug("TCP16 read/protocol error for %s (chunk %d): %s", ip, i, e, exc_info=True)
            label, detail, _ = classify_read_error(e, 0, stage=connection_state["stage"])
            if i == 0:
                return "[green]Да[/green]", label, detail, measured_rtt
            if i < min_detect_chunk:  # вне детект-диапазона DPI
                return alive_str, "[red]TIMEOUT[/red]", detail, measured_rtt
            return alive_str, "[bold red]DETECTED[/bold red]", f"{detail} at {i*chunk_size//1024}KB", measured_rtt

    return alive_str, "[green]OK[/green]", "", measured_rtt



async def check_tcp_16_20(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore,
    hint_rtt: Optional[float] = None,
) -> Tuple[str, str, str, Optional[float]]:
    async with semaphore:
        return await probe_tcp_16_20(ip, port, sni, hint_rtt)


async def probe_tcp_16_20(
    ip: str, port: int, sni: Optional[str],
    hint_rtt: Optional[float] = None,
) -> Tuple[str, str, str, Optional[float]]:
    # max_keepalive_connections=1 гарантирует, что httpx будет пытаться
    # переиспользовать один и тот же сокет для всех запросов к одному IP
    limits = httpx.Limits(max_keepalive_connections=1, max_connections=1)

    proxy_url = getattr(config, "PROXY_URL", None)

    ctx = create_insecure_dpi_ssl_context()
    async with httpx.AsyncClient(
        verify=ctx,
        http2=False,
        limits=limits,
        proxy=proxy_url,
        trust_env=False
    ) as client:
        return await _fat_probe_keepalive(client, ip, port, sni, hint_rtt=hint_rtt)


async def check_tcp_16_20_with_rtt(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore,
) -> Tuple[str, str, str, Optional[float]]:
    """
    Выполняет проверку TCP 16-20KB и возвращает измеренный RTT (4-й элемент).
    RTT измеряется на чистом соединении внутри _fat_probe_keepalive.
    """
    return await check_tcp_16_20(ip, port, sni, semaphore)
