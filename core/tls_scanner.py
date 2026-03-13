import ssl
import time
import math
import errno
import asyncio
import socket
from typing import Tuple
from urllib.parse import urlparse

import httpx

from utils import config
from utils.error_classifier import (
    classify_ssl_error, classify_connect_error, classify_read_error,
    collect_error_text, find_cause, get_errno_from_chain,
)


def create_dpi_client(tls_version: str = None, ipv6: bool = False) -> httpx.AsyncClient:
    """
    Создаёт изолированного клиента для DPI-проверки.
    Тройная гарантия свежего TCP-соединения на каждый запрос:
      1. max_keepalive_connections=0 — отключает пул keep-alive на уровне transport
      2. Connection: close — HTTP-заголовок, закрывает сокет после ответа
      3. follow_redirects=False — клиент не меняет своё состояние между запросами
    Один клиент безопасно используется из множества конкурентных корутин:
    AsyncClient в httpx защищён внутренними asyncio.Lock.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    if tls_version == "TLSv1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    limits = httpx.Limits(max_keepalive_connections=0, max_connections=config.MAX_CONCURRENT)
    transport = httpx.AsyncHTTPTransport(verify=ctx, http2=False, retries=0, limits=limits)

    custom_timeout = httpx.Timeout(
        config.READ_TIMEOUT,
        connect=config.CONNECT_TIMEOUT,
        pool=config.POOL_TIMEOUT
    )

    return httpx.AsyncClient(
        transport=transport,
        timeout=custom_timeout,
        follow_redirects=False,
    )


async def _check_tls_single(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    resolved_ip: str = None,
) -> Tuple[str, str, int, float]:
    """
    Одна попытка TLS-проверки. Клиент передаётся снаружи и переиспользуется.
    resolved_ip: если передан, подключаемся к нему напрямую (нужно для IPv6 — системный
    резолвер может вернуть IPv4 даже если домен имеет AAAA запись).
    """
    bytes_read = 0
    url = f"https://{domain}"

    async with semaphore:
        start = time.time()

        try:
            req = client.build_request(
                "GET",
                url,
                headers={
                    "User-Agent": config.USER_AGENT,
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                }
            )
            response = await client.send(req, stream=True)
            status_code = response.status_code
            location = response.headers.get("location", "")

            if status_code == 451:
                await response.aclose()
                return ("[bold red]BLOCKED[/bold red]", "HTTP 451", bytes_read, time.time() - start)

            if location:
                location_lower = location.lower()
                if any(m in location_lower for m in config.BLOCK_MARKERS):
                    await response.aclose()
                    return ("[bold red]ISP PAGE[/bold red]", "Редирект на блок-страницу", bytes_read, time.time() - start)

                try:
                    parsed_loc = urlparse(
                        location if location.startswith('http') else f'https://{location}'
                    )
                    loc_domain = parsed_loc.netloc.lower()
                    clean_domain = domain.lower().replace('www.', '')
                    clean_loc = loc_domain.replace('www.', '')

                    if loc_domain and clean_loc != clean_domain \
                            and not clean_loc.endswith('.' + clean_domain):
                        cdn_patterns = [
                            'cloudflare', 'akamai', 'fastly', 'cdn', 'cloudfront',
                            'auth', 'login', 'accounts', 'id.', 'sso.',
                        ]
                        if not any(p in clean_loc for p in cdn_patterns):
                            await response.aclose()
                            return (
                                "[bold red]ISP PAGE[/bold red]",
                                f"→ {loc_domain[:20]}",
                                bytes_read,
                                time.time() - start,
                            )
                except Exception:
                    pass

            if 300 <= status_code < 400:
                await response.aclose()
                return ("[green]OK[/green]", "", bytes_read, time.time() - start)

            elapsed = time.time() - start

            if status_code == 200:
                content_length = response.headers.get("content-length", "")
                try:
                    content_len = int(content_length) if content_length else 0
                except Exception:
                    content_len = 0

                if 0 < content_len < config.BODY_INSPECT_LIMIT:
                    body = b""
                    try:
                        async for chunk in response.aiter_bytes(chunk_size=128):
                            body += chunk
                            if len(body) >= config.BODY_INSPECT_LIMIT:
                                break
                    except Exception:
                        pass

                    body_text = body.decode("utf-8", errors="ignore").lower()
                    if any(m in body_text for m in config.BODY_BLOCK_MARKERS):
                        await response.aclose()
                        return ("[bold red]ISP PAGE[/bold red]", "Блок-страница в теле", len(body), elapsed)

            await response.aclose()

            if 200 <= status_code < 500:
                return ("[green]OK[/green]", "", bytes_read, elapsed)
            else:
                return ("[green]OK[/green]", f"HTTP {status_code}", bytes_read, elapsed)

        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            label, detail, br = classify_connect_error(e, bytes_read)
            return (label, detail, br, time.time() - start)

        except httpx.ReadTimeout:
            kb_read = math.ceil(bytes_read / 1024)
            elapsed = time.time() - start
            if config.TCP_BLOCK_MIN_KB <= kb_read <= config.TCP_BLOCK_MAX_KB:
                return ("[bold red]TCP16-20[/bold red]", f"Timeout {kb_read:.1f}KB", bytes_read, elapsed)
            if kb_read > 0:
                return ("[red]TIMEOUT[/red]", f"Read timeout {kb_read:.1f}KB", bytes_read, elapsed)
            return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read, elapsed)

        except ssl.SSLError as e:
            label, detail, br = classify_ssl_error(e, bytes_read)
            return (label, detail, br, time.time() - start)

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            label, detail, br = classify_read_error(e, bytes_read)
            return (label, detail, br, time.time() - start)

        except OSError as e:
            elapsed = time.time() - start
            en = e.errno
            if en in (errno.ECONNRESET, config.WSAECONNRESET):
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read, elapsed)
            elif en in (errno.ECONNREFUSED, config.WSAECONNREFUSED):
                return ("[bold red]REFUSED[/bold red]", "OS conn refused", bytes_read, elapsed)
            elif en in (errno.ETIMEDOUT, config.WSAETIMEDOUT):
                return ("[red]TIMEOUT[/red]", "OS timeout", bytes_read, elapsed)
            else:
                return ("[red]OS ERR[/red]", f"errno={en}", bytes_read, elapsed)

        except Exception as e:
            return ("[red]ERR[/red]", f"{type(e).__name__}", bytes_read, time.time() - start)


async def check_domain_tls(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, str, float]:
    """Одна TLS-проверка. Возвращает (status, detail, elapsed)."""
    status, detail, _, elapsed = await _check_tls_single(domain, client, semaphore)

    return (status, detail, elapsed)


async def check_http_injection(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> Tuple[str, str]:
    """Проверяет HTTP-инжекцию (plain HTTP). Клиент передаётся снаружи."""
    clean_domain = domain.replace("https://", "").replace("http://", "")

    try:
        req = client.build_request(
            "GET",
            f"http://{clean_domain}",
            headers={
                "User-Agent": config.USER_AGENT,
                "Accept-Encoding": "identity",
                "Connection": "close",
            }
        )
        response = await client.send(req, stream=True)
        status_code = response.status_code
        location = response.headers.get("location", "")

        if status_code == 451:
            await response.aclose()
            return ("[bold red]BLOCKED[/bold red]", "HTTP 451")

        if any(m in location.lower() for m in config.BLOCK_MARKERS):
            await response.aclose()
            return ("[bold red]ISP PAGE[/bold red]", "Блок-страница")

        if 200 <= status_code < 300:
            body = b""
            try:
                async for chunk in response.aiter_bytes(chunk_size=128):
                    body += chunk
                    if len(body) >= config.BODY_INSPECT_LIMIT:
                        break
            except Exception:
                pass
            await response.aclose()

            body_text = body.decode("utf-8", errors="ignore").lower()
            if any(m in body_text for m in config.BODY_BLOCK_MARKERS):
                return ("[bold red]ISP PAGE[/bold red]", "Блок-страница (HTTP)")
            return ("[green]OK[/green]", f"{status_code}")

        if 300 <= status_code < 400:
            await response.aclose()
            return ("[green]REDIR[/green]", f"{status_code}")

        await response.aclose()
        return ("[green]OK[/green]", f"{status_code}")

    except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            label, detail, _ = classify_connect_error(e, 0)
            return (label, detail)

    except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as e:
        err_type = type(e).__name__.replace("Timeout", "").upper() + " TIMEOUT"
        return (f"[red]{err_type}[/red]", "Timeout")

    except (httpx.ReadError, httpx.RemoteProtocolError, Exception) as e:
        label, detail, _ = classify_read_error(e, 0)
        return (label, detail)