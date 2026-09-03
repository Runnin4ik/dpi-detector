import asyncio
import contextlib
import ssl
import time
from utils.network import get_fake_ip_type, get_resolved_ip, format_ip_for_url
from typing import Tuple, Optional
from urllib.parse import urlparse
import errno

import httpx

from utils import config
from utils.error_classifier import (
    classify_ssl_error, classify_connect_error, classify_read_error,
    get_exception_chain_full
)
from utils.network import create_insecure_dpi_ssl_context


def _strip_www(host: str) -> str:
    """Убирает префикс 'www.' (аналог str.removeprefix, которого нет в Python 3.8)."""
    return host[4:] if host.startswith("www.") else host


def create_dpi_client(tls_version: str = None) -> httpx.AsyncClient:
    """
    Создаёт изолированного клиента для DPI-проверки.
    Тройная гарантия свежего TCP-соединения на каждый запрос:
      1. max_keepalive_connections=0 — отключает пул keep-alive на уровне transport
      2. Connection: close — HTTP-заголовок, закрывает сокет после ответа
      3. follow_redirects=False — клиент не меняет своё состояние между запросами
    Один клиент безопасно используется из множества конкурентных корутин:
    AsyncClient в httpx защищён внутренними asyncio.Lock.
    """
    # ВНИМАНИЕ: CERT_NONE и check_hostname=False используются ИСКЛЮЧИТЕЛЬНО для
    # DPI-зондирования (детекция MITM/подмены сертификатов DPI и анализ L4-блокировок).
    # Этот контекст категорически ЗАПРЕЩЕНО использовать для передачи учетных данных,
    # запросов к GitHub API или обновления программы (там используется строгая валидация CA).
    ctx = create_insecure_dpi_ssl_context(tls_version=tls_version)
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

import logging
from logging.handlers import RotatingFileHandler

logger = logging.getLogger(__name__)
_debug_file_logger: Optional[logging.Logger] = None


def _get_debug_file_logger() -> logging.Logger:
    global _debug_file_logger
    if _debug_file_logger is None:
        _debug_file_logger = logging.getLogger("dpi_detector.debug_errors")
        _debug_file_logger.setLevel(logging.DEBUG)
        _debug_file_logger.propagate = False
        try:
            handler = RotatingFileHandler(
                "debug_errors.log",
                maxBytes=5 * 1024 * 1024,  # 5 МБ
                backupCount=3,
                encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
            _debug_file_logger.addHandler(handler)
        except Exception as e:
            logger.debug("RotatingFileHandler error: %s", e)
    return _debug_file_logger


def log_debug_error(domain: str, stage: str, exc: Exception):
    """Логирование ошибки в debug-логгер и в ротируемый файл при config.DEBUG."""
    full_info = get_exception_chain_full(exc)
    logger.debug("%s (stage: %s): %s", domain, stage, full_info)
    if getattr(config, "DEBUG", False):
        try:
            f_logger = _get_debug_file_logger()
            f_logger.debug("%-20s | STAGE: %-15s | %s", domain, stage, full_info)
        except Exception:
            pass

async def _check_tls_single(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: Optional[asyncio.Semaphore] = None,
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

    # Привязка к IP выбранного семейства: соединение по A-/AAAA-записи,
    # SNI и Host — от домена.
    if resolved_ip is None and not getattr(config, "PROXY_URL", None):
        resolved_ip = await get_resolved_ip(domain)

    if resolved_ip:
        fake_type = get_fake_ip_type(resolved_ip)

        # Если это не Fake-IP, но адрес есть в заглушках провайдера -> это ISP
        if fake_type != "fakeip" and stub_ips and resolved_ip in stub_ips:
            fake_type = "isp"

        if fake_type == "isp":
            return ("[bold red]ISP PAGE[/bold red]", f"Заглушка провайдера {resolved_ip}", 0, 0.0)
        if fake_type == "local":
            return ("[bold yellow]LOCAL IP[/bold yellow]", f"Локальный IP {resolved_ip}", 0, 0.0)

    req_url, sni_ext = url, {}
    if resolved_ip:
        req_url = f"https://{format_ip_for_url(resolved_ip)}"
        sni_ext = {"sni_hostname": domain}
    connection_state = {"stage": "init"}
    async def trace_hook(event_name, info):
        if event_name == "connection.connect_tcp.started":
            connection_state["stage"] = "tcp_connect"
        elif event_name == "connection.connect_tcp.complete":
            connection_state["stage"] = "tcp_connected"
        elif event_name == "connection.start_tls.started":
            connection_state["stage"] = "tls_handshake"
        elif event_name == "connection.start_tls.complete":
            connection_state["stage"] = "tls_connected"
        elif "send_request" in event_name:
            connection_state["stage"] = "sending_data"
        elif "receive_response" in event_name:
            connection_state["stage"] = "reading_data"

    sem_ctx = semaphore if semaphore is not None else contextlib.nullcontext()
    async with sem_ctx:
        start = time.monotonic()

        try:
            req = client.build_request(
                "GET",
                req_url,
                headers={
                    "User-Agent": config.USER_AGENT,
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    **({"Host": domain} if sni_ext else {}),
                },
                extensions={"trace": trace_hook, **sni_ext}
            )
            response = await client.send(req, stream=True)
            status_code = response.status_code
            location = response.headers.get("location", "")

            if status_code == 451:
                await response.aclose()
                return ("[bold red]BLOCKED[/bold red]", "HTTP 451", bytes_read, time.monotonic() - start)

            if location and 300 <= status_code < 400:
                await response.aclose()
                elapsed = time.monotonic() - start
                try:
                    from urllib.parse import urljoin
                    resolved_url = urljoin(url, location)
                    parsed_loc = urlparse(resolved_url)
                    loc_domain = parsed_loc.hostname or ""
                    norm_loc = _strip_www(loc_domain.lower())
                    norm_dom = _strip_www(domain.lower())

                    same_host = norm_loc == norm_dom or norm_loc.endswith('.' + norm_dom)
                    if same_host and parsed_loc.scheme == "https":
                        # тот же сайт, просто апгрейд до https — считаем ОК
                        return ("[green]OK[/green]", "→ https", bytes_read, elapsed)
                    if same_host:
                        return ("[green]REDIR[/green]", f"→ {loc_domain[:30]}", bytes_read, elapsed)
                    return ("[bold red]REDIR[/bold red]", f"→ {loc_domain[:30]}", bytes_read, elapsed)
                except Exception:
                    return ("[bold red]REDIR[/bold red]", f"→ {location[:30]}", bytes_read, elapsed)
            if 300 <= status_code < 400:
                await response.aclose()
                return ("[green]REDIR[/green]", "", bytes_read, time.monotonic() - start)

            try:
                async for chunk in response.aiter_bytes():
                    bytes_read += len(chunk)
                    if bytes_read >= 64 * 1024:
                        break
            finally:
                await response.aclose()
            elapsed = time.monotonic() - start
            if 200 <= status_code < 500:
                return ("[green]OK[/green]", "", bytes_read, elapsed)
            return ("[green]OK[/green]", f"HTTP {status_code}", bytes_read, elapsed)

        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            log_debug_error(domain, connection_state["stage"], e)
            label, detail, br = classify_connect_error(e, bytes_read, stage=connection_state["stage"])
            return (label, detail, br, time.monotonic() - start)

        except httpx.ReadTimeout as e:
            log_debug_error(domain, connection_state["stage"], e)
            kb_read = bytes_read / 1024
            elapsed = time.monotonic() - start
            if config.TCP_BLOCK_MIN_KB <= kb_read <= config.TCP_BLOCK_MAX_KB:
                return ("[bold red]TCP16-20[/bold red]", f"Timeout {kb_read:.1f}KB", bytes_read, elapsed)
            if kb_read > 0:
                return ("[red]TIMEOUT[/red]", f"Read timeout {kb_read:.1f}KB", bytes_read, elapsed)
            return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read, elapsed)

        except ssl.SSLError as e:
            log_debug_error(domain, connection_state["stage"], e)
            label, detail, br = classify_ssl_error(e, bytes_read, stage=connection_state["stage"])
            return (label, detail, br, time.monotonic() - start)

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            log_debug_error(domain, connection_state["stage"], e)
            label, detail, br = classify_read_error(e, bytes_read, stage=connection_state["stage"])
            return (label, detail, br, time.monotonic() - start)

        except OSError as e:
            log_debug_error(domain, connection_state["stage"], e)
            elapsed = time.monotonic() - start
            en = e.errno
            if en in (errno.ECONNRESET, getattr(config, "WSAECONNRESET", 10054)):
                if connection_state["stage"] == "tls_handshake":
                    return ("[bold red]TLS RST[/bold red]", "TCP RST на ClientHello", bytes_read, elapsed)
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read, elapsed)
            if en in (errno.ECONNREFUSED, getattr(config, "WSAECONNREFUSED", 10061)):
                return ("[bold red]REFUSED[/bold red]", "OS conn refused", bytes_read, elapsed)
            if en in (errno.ETIMEDOUT, getattr(config, "WSAETIMEDOUT", 10060)):
                return ("[red]TIMEOUT[/red]", "OS timeout", bytes_read, elapsed)
            return ("[red]OS ERR[/red]", f"errno={en}", bytes_read, elapsed)

        except Exception as e:
            log_debug_error(domain, connection_state["stage"], e)
            return ("[red]ERR[/red]", f"{type(e).__name__}", bytes_read, time.monotonic() - start)


async def check_domain_tls(
    domain: str,
    client: httpx.AsyncClient,
    semaphore: Optional[asyncio.Semaphore] = None,
    stub_ips: set = None,
    resolved_ip: str = None,
) -> Tuple[str, str, float]:
    status, detail, _, elapsed = await _check_tls_single(
        domain, client, semaphore, resolved_ip=resolved_ip, stub_ips=stub_ips
    )
    return (status, detail, elapsed)

async def check_http_injection(
    domain: str,
    client: httpx.AsyncClient,
    stub_ips: set = None,
) -> Tuple[str, str]:
    """Проверяет HTTP-инжекцию (plain HTTP). Клиент передаётся снаружи."""
    clean_domain = domain.replace("https://", "").replace("http://", "")
    # Привязка к IP выбранного семейства: соединение по A-/AAAA-записи,
    # Host остаётся доменом.
    http_target = f"http://{clean_domain}"
    if not getattr(config, "PROXY_URL", None):
        _ip = await get_resolved_ip(clean_domain)
        if _ip:
            if stub_ips and _ip in stub_ips:
                return ("[bold red]ISP PAGE[/bold red]", f"Заглушка провайдера {_ip}")
            http_target = f"http://{format_ip_for_url(_ip)}"
    connection_state = {"stage": "init"}
    async def trace_hook(event_name, info):
        if event_name == "connection.connect_tcp.started":
            connection_state["stage"] = "tcp_connect"
        elif event_name == "connection.connect_tcp.complete":
            connection_state["stage"] = "tcp_connected"
        elif "send_request" in event_name:
            connection_state["stage"] = "sending_data"
        elif "receive_response" in event_name:
            connection_state["stage"] = "reading_data"

    try:
        req = client.build_request(
            "HEAD",
            http_target,
            headers={
                "User-Agent": config.USER_AGENT,
                "Host": clean_domain,
                "Accept": "*/*",
                "Connection": "close",
            },
            extensions={"trace": trace_hook}
        )
        response = await client.send(req)
        status_code = response.status_code
        location = response.headers.get("location", "")

        if status_code == 451:
            await response.aclose()
            return ("[bold red]BLOCKED[/bold red]", "HTTP 451")

        if location and 300 <= status_code < 400:
            await response.aclose()
            try:
                from urllib.parse import urljoin
                resolved_url = urljoin(http_target, location)
                parsed_loc = urlparse(resolved_url)
                loc_domain = parsed_loc.hostname or ""
                norm_loc = _strip_www(loc_domain.lower())
                norm_dom = _strip_www(clean_domain.lower())
                same_host = norm_loc == norm_dom or norm_loc.endswith('.' + norm_dom)
                if same_host and parsed_loc.scheme == "https":
                    # http → https на том же сайте — норма, считаем ОК
                    return ("[green]OK[/green]", f"{status_code} → https")
                if same_host:
                    return ("[green]REDIR[/green]", f"{status_code}")
                return ("[bold red]REDIR[/bold red]", f"→ {loc_domain[:30]}")
            except Exception:
                return ("[bold red]REDIR[/bold red]", f"→ {location[:30]}")
        if 300 <= status_code < 400:
            await response.aclose()
            return ("[green]REDIR[/green]", f"{status_code}")

        await response.aclose()

        return ("[green]OK[/green]", f"{status_code}")
    except (httpx.ConnectTimeout, httpx.ConnectError) as e:
        log_debug_error(domain, connection_state["stage"], e)
        label, detail, _ = classify_connect_error(e, 0, stage=connection_state["stage"])
        return (label, detail)

    except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as e:
        log_debug_error(domain, connection_state["stage"], e)
        err_type = type(e).__name__.replace("Timeout", "").upper() + " TIMEOUT"
        return (f"[red]{err_type}[/red]", "Timeout")

    except (httpx.ReadError, httpx.RemoteProtocolError, Exception) as e:
        log_debug_error(domain, connection_state["stage"], e)
        label, detail, _ = classify_read_error(e, 0)
        return (label, detail)
