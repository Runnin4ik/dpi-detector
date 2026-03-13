import os
import ssl
import asyncio
import random
import string
import time
from typing import Tuple, Optional
import httpx
from utils import config
from utils.error_classifier import classify_connect_error, classify_read_error

# Предварительно генерируем пул случайных символов (100 КБ).
RANDOM_POOL = "".join(random.choices(string.ascii_letters + string.digits, k=100_000))


async def _fat_probe_keepalive(
    client: httpx.AsyncClient, ip: str, port: int, sni: Optional[str],
    hint_rtt: Optional[float] = None,
) -> Tuple[str, str, str]:
    """
    hint_rtt: если передан известный RTT (сек) — пропускаем фазу измерения
    и сразу используем его для dynamic_timeout. Ускоряет перебор SNI.
    """
    scheme = "http" if port == 80 else "https"
    url = f"{scheme}://{ip}:{port}/"

    base_headers = {
        "User-Agent": config.USER_AGENT,
        "Connection": "keep-alive"
    }
    if sni:
        base_headers["Host"] = sni

    alive_str = "[dim]—[/dim]"
    chunks_count = 16
    chunk_size = 4000

    rtt_measurements = []
    # Если RTT известен заранее — сразу выставляем dynamic_timeout
    if hint_rtt is not None:
        dyn_t = max(hint_rtt * 3.0, 1.5)
        dynamic_timeout = min(dyn_t, config.FAT_READ_TIMEOUT)
    else:
        dynamic_timeout = None

    extensions = {}
    if sni and port != 80:
        extensions["sni_hostname"] = sni

    for i in range(chunks_count):
        headers = base_headers.copy()
        # i=0 — чистый запрос без X-Pad: только проверяем что сервер живой.
        # i>=1 — добавляем мусор
        if i > 0:
            start_idx = random.randint(0, len(RANDOM_POOL) - chunk_size - 1)
            headers["X-Pad"] = RANDOM_POOL[start_idx:start_idx + chunk_size]

        timeout_read = dynamic_timeout if dynamic_timeout is not None else config.FAT_READ_TIMEOUT
        custom_timeout = httpx.Timeout(
            timeout_read,
            connect=config.FAT_CONNECT_TIMEOUT,
            pool=config.POOL_TIMEOUT
        )

        start_time = time.time()

        try:
            resp = await client.request(
                "HEAD", url, headers=headers,
                timeout=custom_timeout,
                extensions=extensions if extensions else None
            )

            elapsed = time.time() - start_time

            if i == 0:
                alive_str = "[green]Да[/green]"

            # Измеряем RTT на первых 2 запросах только если hint не был передан
            if hint_rtt is None and i < 2:
                rtt_measurements.append(elapsed)
                if len(rtt_measurements) == 2:
                    base_rtt = max(rtt_measurements)
                    dyn_t = max(base_rtt * 3.0, 1.5)
                    dynamic_timeout = min(dyn_t, config.FAT_READ_TIMEOUT)

            await asyncio.sleep(0.05)

        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            label, detail, _ = classify_connect_error(e, 0)
            if i == 0:
                return "[red]Нет[/red]", label, detail
            return alive_str, "[bold red]DETECTED[/bold red]", f"{detail} at {i*4}KB"

        except (httpx.ReadTimeout, httpx.WriteTimeout) as e:
            err_type = "Read Timeout" if isinstance(e, httpx.ReadTimeout) else "Write Timeout"
            if i == 0:
                return "[green]Да[/green]", f"[red]{err_type.upper()}[/red]", err_type
            return alive_str, "[bold red]DETECTED[/bold red]", f"{err_type} at {i*4}KB"

        except Exception as e:
            # Для ReadError, WriteError, RemoteProtocolError и любых других
            label, detail, _ = classify_read_error(e, 0)
            if i == 0:
                return "[green]Да[/green]", label, detail
            return alive_str, "[bold red]DETECTED[/bold red]", f"{detail} at {i*4}KB"

    return alive_str, "[green]OK[/green]", ""


async def check_tcp_16_20(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore,
    hint_rtt: Optional[float] = None,
) -> Tuple[str, str, str]:
    async with semaphore:
        verify_ctx = ssl.create_default_context()
        verify_ctx.check_hostname = False
        verify_ctx.verify_mode = ssl.CERT_NONE

        # max_keepalive_connections=1 гарантирует, что httpx будет пытаться
        # переиспользовать один и тот же сокет для всех запросов к одному IP
        limits = httpx.Limits(max_keepalive_connections=1, max_connections=1)

        async with httpx.AsyncClient(verify=verify_ctx, http2=False, limits=limits) as client:
            return await _fat_probe_keepalive(client, ip, port, sni, hint_rtt=hint_rtt)


async def check_tcp_16_20_with_rtt(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore,
) -> Tuple[str, str, str, Optional[float]]:
    """
    Как check_tcp_16_20, но дополнительно возвращает измеренный RTT (4й элемент).
    RTT = среднее первых двух успешных запросов. None если измерить не удалось.
    Используется в тесте 4 чтобы передать hint_rtt при перебое SNI.
    """
    async with semaphore:
        verify_ctx = ssl.create_default_context()
        verify_ctx.check_hostname = False
        verify_ctx.verify_mode = ssl.CERT_NONE

        limits = httpx.Limits(max_keepalive_connections=1, max_connections=1)

        rtt_samples = []
        original_sleep = asyncio.sleep

        async with httpx.AsyncClient(verify=verify_ctx, http2=False, limits=limits) as client:
            scheme = "http" if port == 80 else "https"
            url = f"{scheme}://{ip}:{port}/"
            base_headers = {"User-Agent": config.USER_AGENT, "Connection": "keep-alive"}
            if sni:
                base_headers["Host"] = sni
            extensions = {"sni_hostname": sni} if sni and port != 80 else {}

            measured_rtt = None
            try:
                t0 = time.time()
                await client.request(
                    "HEAD", url, headers=base_headers,
                    timeout=config.FAT_READ_TIMEOUT,
                    extensions=extensions if extensions else None,
                )
                measured_rtt = time.time() - t0
            except Exception:
                pass

            result = await _fat_probe_keepalive(client, ip, port, sni, hint_rtt=measured_rtt)
            return result[0], result[1], result[2], measured_rtt