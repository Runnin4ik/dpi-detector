import ssl
import time
import math
import errno
import asyncio
import socket
from utils.network import get_fake_ip_type
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
    proxy_url = getattr(config, "PROXY_URL", None)

    transport = httpx.AsyncHTTPTransport(
        verify=ctx,
        http2=False,
        retries=0,
        limits=limits,
        proxy=proxy_url
    )

    custom_timeout = httpx.Timeout(
        config.READ_TIMEOUT,
        connect=config.CONNECT_TIMEOUT,
        pool=config.POOL_TIMEOUT
    )

    return httpx.AsyncClient(
        transport=transport,
        timeout=custom_timeout,
        follow_redirects=False,
        trust_env=False
    )


async def _check_tls_single(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    resolved_ip: str = None,
    stub_ips: set = None,
) -> Tuple[str, str, int, float]:
    """
    Одна попытка TLS-проверки. Клиент передаётся снаружи и переиспользуется.
    stub_ips: если передан, редирект на IP из этого набора помечается как ISP PAGE.
    resolved_ip: если передан, подключаемся к нему напрямую.

    Логика редиректов:
      - Редирект на тот же домен или поддомен → зелёный REDIR (ОК)
      - Редирект на чужой домен → красный REDIR (подозрительно)
      - Если resolved_ip входит в stub_ips → ISP PAGE
    """
    bytes_read = 0
    url = f"https://{domain}"

    if resolved_ip:
        fake_type = get_fake_ip_type(resolved_ip)

        # Если это не Fake-IP, но адрес есть в заглушках провайдера -> это ISP
        if fake_type != "fakeip" and stub_ips and resolved_ip in stub_ips:
            fake_type = "isp"

        if fake_type == "isp":
            return ("[bold red]ISP PAGE[/bold red]", f"Заглушка провайдера {resolved_ip}", 0, 0.0)
        elif fake_type == "local":
            return ("[bold yellow]LOCAL IP[/bold yellow]", f"Локальный IP {resolved_ip}", 0, 0.0)

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

            if location and 300 <= status_code < 400:
                await response.aclose()
                elapsed = time.time() - start
                try:
                    parsed_loc = urlparse(
                        location if location.startswith('http') else f'https://{location}'
                    )
                    loc_domain = parsed_loc.netloc.lower().split(':')[0]
                    clean_domain = domain.lower()
                    norm_loc = loc_domain.removeprefix('www.')
                    norm_dom = clean_domain.removeprefix('www.')

                    if norm_loc == norm_dom or norm_loc.endswith('.' + norm_dom):
                        return ("[green]REDIR[/green]", f"→ {loc_domain[:30]}", bytes_read, elapsed)
                    else:
                        return ("[bold red]REDIR[/bold red]", f"→ {loc_domain[:30]}", bytes_read, elapsed)
                except Exception:
                    return ("[bold red]REDIR[/bold red]", f"→ {location[:30]}", bytes_read, elapsed)

            if 300 <= status_code < 400:
                await response.aclose()
                return ("[green]REDIR[/green]", "", bytes_read, time.time() - start)

            await response.aclose()
            elapsed = time.time() - start

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
    stub_ips: set = None,
    resolved_ip: str = None,
) -> Tuple[str, str, float]:
    """Одна TLS-проверка. Возвращает (status, detail, elapsed)."""
    status, detail, _, elapsed = await _check_tls_single(
        domain, client, semaphore, resolved_ip=resolved_ip, stub_ips=stub_ips
    )
    return (status, detail, elapsed)


async def check_http_injection(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    stub_ips: set = None,
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

        if location and 300 <= status_code < 400:
            await response.aclose()
            try:
                parsed_loc = urlparse(
                    location if location.startswith('http') else f'https://{location}'
                )
                loc_domain = parsed_loc.netloc.lower().split(':')[0]
                norm_loc = loc_domain.removeprefix('www.')
                norm_dom = clean_domain.lower().removeprefix('www.')
                if norm_loc == norm_dom or norm_loc.endswith('.' + norm_dom):
                    return ("[green]REDIR[/green]", f"{status_code}")
                else:
                    return ("[bold red]REDIR[/bold red]", f"→ {loc_domain[:30]}")
            except Exception:
                return ("[bold red]REDIR[/bold red]", f"→ {location[:30]}")

        if 300 <= status_code < 400:
            await response.aclose()
            return ("[green]REDIR[/green]", f"{status_code}")

        await response.aclose()

        if 200 <= status_code < 300:
            return ("[green]OK[/green]", f"{status_code}")

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