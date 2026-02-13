import asyncio
import ssl
import sys
import socket
import warnings
import time
import errno
import re
import math
import config
from typing import Tuple, Optional, List  # Добавлен импорт для type hints
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

try:
    import httpx
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError as e:
    print(f"Ошибка: {e}")
    print("Установите зависимости: pip install httpx rich")
    sys.exit(1)

console = Console()

# =================== Конфиг
USE_IPV4_ONLY = config.USE_IPV4_ONLY
MAX_CONCURRENT = config.MAX_CONCURRENT
TIMEOUT = config.TIMEOUT
TIMEOUT_TCP_16_20 = config.TIMEOUT_TCP_16_20
DOMAIN_CHECK_RETRIES = config.DOMAIN_CHECK_RETRIES
TCP_16_20_CHECK_RETRIES = config.TCP_16_20_CHECK_RETRIES
TCP_BLOCK_MIN_KB = config.TCP_BLOCK_MIN_KB
TCP_BLOCK_MAX_KB = config.TCP_BLOCK_MAX_KB
SHOW_DATA_SIZE = config.SHOW_DATA_SIZE
BODY_INSPECT_LIMIT = config.BODY_INSPECT_LIMIT
DATA_READ_THRESHOLD = config.DATA_READ_THRESHOLD
USER_AGENT = config.USER_AGENT
BLOCK_MARKERS = config.BLOCK_MARKERS
BODY_BLOCK_MARKERS = config.BODY_BLOCK_MARKERS
WSAECONNRESET = config.WSAECONNRESET
WSAECONNREFUSED = config.WSAECONNREFUSED
WSAETIMEDOUT = config.WSAETIMEDOUT
WSAENETUNREACH = config.WSAENETUNREACH
WSAEHOSTUNREACH = config.WSAEHOSTUNREACH
WSAECONNABORTED = config.WSAECONNABORTED
WSAENETDOWN = config.WSAENETDOWN
WSAEACCES = config.WSAEACCES
DPI_VARIANCE_THRESHOLD = config.DPI_VARIANCE_THRESHOLD


def load_domains(filepath="domains.txt"):
    """Загружает домены из файла."""
    domains = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except FileNotFoundError:
        console.print(f"[red]Файл {filepath} не найден![/red]")
    return domains

def load_tcp_targets(filepath="tcp_16_20_targets.json"):
    """Загружает TCP цели из JSON."""
    import json
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[red]Файл {filepath} не найден![/red]")
        return []

DOMAINS = load_domains()
TCP_16_20_ITEMS = load_tcp_targets()

# ============================================================================ Хелперы для анализа ошибок

if USE_IPV4_ONLY:
    # Патчим socket.getaddrinfo для использования только IPv4
    import socket as _socket
    _original_getaddrinfo = _socket.getaddrinfo

    def _getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
        """Возвращает только IPv4 адреса."""
        return _original_getaddrinfo(host, port, _socket.AF_INET, type, proto, flags)

    _socket.getaddrinfo = _getaddrinfo_ipv4_only


def _find_cause_of_type(exc: Exception, target_type: type, max_depth: int = 10):
    """Ищет в цепочке ошибок первое исключение заданного типа."""
    current = exc
    for _ in range(max_depth):
        if isinstance(current, target_type):
            return current
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _get_errno_from_chain(exc: Exception, max_depth: int = 10) -> Optional[int]:
    """Извлекает errno из цепочки ошибок."""
    current = exc
    for _ in range(max_depth):
        if isinstance(current, OSError) and current.errno is not None:
            return current.errno
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def _collect_error_text(exc: Exception, max_depth: int = 10) -> str:
    """Собирает текст из всей цепочки исключений."""
    parts = []
    current = exc
    for _ in range(max_depth):
        parts.append(str(current).lower())
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return " | ".join(parts)


def _clean_detail(detail: str) -> str:
    """Очистка деталей от лишнего текста."""
    if not detail or detail in ("OK", "Error"):
        return ""

    # Убираем длинные фразы
    detail = detail.replace("The operation did not complete", "TLS Aborted")

    # Убираем всё в скобках и незакрытые скобки
    detail = re.sub(r"\s*\([^)]*\)?\s*", " ", detail)
    detail = re.sub(r"\s*\(_*\s*$", "", detail)

    # Убираем лишние пробелы и технические префиксы
    detail = re.sub(r"\s+", " ", detail).strip()
    detail = detail.replace("Err None: ", "").replace("Conn failed: ", "")

    # Убираем HTTP статусы (не информативны если OK)
    if re.match(r"^HTTP [23]\d\d$", detail):
        return ""

    return detail.strip()


def _format_data_size(bytes_count: int) -> str:
    """Форматирует размер данных для отображения."""
    if not SHOW_DATA_SIZE or bytes_count == 0:
        return ""


    kb = math.ceil(bytes_count / 1024)
    max_kb = 200

    if kb > max_kb:
        return f"{max_kb:.0f}KB+"
    else:
        return f"{kb:.0f}KB"


# ============================================================================ Классификация ConnectError

def _classify_connect_error(error: httpx.ConnectError, bytes_read: int) -> Tuple[str, str, int]:
    """Глубокая классификация httpx.ConnectError."""
    full_text = _collect_error_text(error)
    err_errno = _get_errno_from_chain(error)

    # DNS ошибки
    gai = _find_cause_of_type(error, socket.gaierror)
    if gai is not None:
        gai_errno = getattr(gai, 'errno', None)
        if gai_errno in (socket.EAI_NONAME, 11001):
            return ("[yellow]DNS FAIL[/yellow]", "Домен не найден", bytes_read)
        elif gai_errno in (getattr(socket, 'EAI_AGAIN', -3), 11002):
            return ("[yellow]DNS FAIL[/yellow]", "DNS таймаут", bytes_read)
        else:
            return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    if any(x in full_text for x in ["getaddrinfo failed", "name resolution", "11001", "11002",
                                      "name or service not known", "nodename nor servname"]):
        return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    # TLS alert внутри ConnectError (DPI)
    if "sslv3_alert" in full_text or "ssl alert" in full_text or ("alert" in full_text and "handshake" in full_text):
        if "handshake_failure" in full_text or "handshake failure" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "Handshake alert", bytes_read)
        elif "unrecognized_name" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "SNI alert", bytes_read)
        elif "protocol_version" in full_text:
            return ("[bold red]TLS BLOCK[/bold red]", "Version alert", bytes_read)
        else:
            return ("[bold red]TLS DPI[/bold red]", "TLS alert", bytes_read)

    # ConnectionRefusedError
    if _find_cause_of_type(error, ConnectionRefusedError) is not None \
       or err_errno in (errno.ECONNREFUSED, WSAECONNREFUSED) \
       or "refused" in full_text:
        return ("[bold red]REFUSED[/bold red]", "Порт закрыт/RST", bytes_read)

    # ConnectionResetError
    if _find_cause_of_type(error, ConnectionResetError) is not None \
       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
       or "connection reset" in full_text:
        return ("[bold red]TCP RST[/bold red]", "RST при handshake", bytes_read)

    # ConnectionAbortedError
    if _find_cause_of_type(error, ConnectionAbortedError) is not None \
       or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED) \
       or "connection aborted" in full_text:
        return ("[bold red]TCP ABORT[/bold red]", "Соединение прервано", bytes_read)

    # TimeoutError
    if _find_cause_of_type(error, TimeoutError) is not None \
       or err_errno in (errno.ETIMEDOUT, WSAETIMEDOUT) \
       or "timed out" in full_text:
        return ("[red]TIMEOUT[/red]", "Таймаут handshake", bytes_read)

    # Network unreachable
    if err_errno in (errno.ENETUNREACH, WSAENETUNREACH) or "network is unreachable" in full_text:
        return ("[red]NET UNREACH[/red]", "Сеть недоступна", bytes_read)
    if err_errno in (errno.EHOSTUNREACH, WSAEHOSTUNREACH) or "no route to host" in full_text:
        return ("[red]HOST UNREACH[/red]", "Хост недоступен", bytes_read)

    # SSL ошибки внутри ConnectError
    ssl_err = _find_cause_of_type(error, ssl.SSLError)
    if ssl_err is not None:
        return _classify_ssl_error(ssl_err, bytes_read)

    # All connection attempts failed
    if "all connection attempts failed" in full_text:
        return ("[bold red]CONN FAIL[/bold red]", "Все попытки провалились", bytes_read)

    short = str(error)[:40].replace("\n", " ")
    return ("[red]CONN ERR[/red]", _clean_detail(short), bytes_read)


# ============================================================================ Классификация SSL-ошибок

def _classify_ssl_error(error: ssl.SSLError, bytes_read: int) -> Tuple[str, str, int]:
    """Детальная классификация ssl.SSLError."""
    error_msg = str(error).lower()

    # SSLCertVerificationError
    if isinstance(error, ssl.SSLCertVerificationError):
        verify_code = getattr(error, 'verify_code', None)
        if verify_code == 10 or "expired" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        elif verify_code in (18, 19) or "self-signed" in error_msg or "self signed" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Self-signed cert", bytes_read)
        elif verify_code == 20 or "unknown ca" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif verify_code == 62 or "hostname mismatch" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Hostname mismatch", bytes_read)
        else:
            return ("[bold red]TLS MITM[/bold red]", "Cert verify fail", bytes_read)

    # SSLZeroReturnError
    if isinstance(error, ssl.SSLZeroReturnError):
        return ("[bold red]TLS CLOSE[/bold red]", "TLS close_notify", bytes_read)

    # Certificate errors
    if "certificate" in error_msg:
        if "verify failed" in error_msg or "unknown ca" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif "hostname mismatch" in error_msg or "name mismatch" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert mismatch", bytes_read)
        elif "expired" in error_msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        else:
            return ("[red]SSL CERT[/red]", "Cert error", bytes_read)

    # TLS version errors
    if "version" in error_msg or "protocol version" in error_msg:
        if "wrong version number" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "Non-TLS response", bytes_read)
        return ("[bold red]TLS BLOCK[/bold red]", "Version block", bytes_read)

    # Cipher suite errors
    if "cipher" in error_msg or "no shared cipher" in error_msg:
        return ("[bold red]TLS MITM[/bold red]", "Cipher mismatch", bytes_read)

    # Handshake errors
    if "handshake" in error_msg:
        if "unexpected" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "HS manipulated", bytes_read)
        elif "alert handshake" in error_msg or "sslv3_alert_handshake" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "HS alert", bytes_read)
        elif "failure" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "HS failure", bytes_read)
        elif "operation did not complete" in error_msg:
            return ("[bold red]TLS DPI[/bold red]", "TLS aborted", bytes_read)
        return ("[red]TLS FAIL[/red]", "HS error", bytes_read)

    # Record-layer errors
    if "record overflow" in error_msg or "oversized" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Record overflow", bytes_read)

    # Illegal parameter / bad mac / decrypt
    if "illegal parameter" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Illegal param", bytes_read)
    if "bad mac" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Bad MAC", bytes_read)
    if "decrypt" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Decrypt error", bytes_read)
    if "decode" in error_msg or "decoding" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Decode error", bytes_read)

    # SNI-related
    if "unrecognized name" in error_msg or "unrecognized_name" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "SNI unrecognized", bytes_read)

    # Internal error
    if "internal error" in error_msg:
        return ("[red]TLS INT[/red]", "Internal error", bytes_read)

    # EOF
    if "eof" in error_msg or "unexpected eof" in error_msg:
        return ("[bold red]TLS DPI[/bold red]", "Unexpected EOF", bytes_read)

    short_msg = _clean_detail(str(error)[:40])
    return ("[red]SSL ERR[/red]", short_msg, bytes_read)


# ============================================================================ Классификация ошибок чтения данных

def _classify_read_error(error: Exception, bytes_read: int) -> Tuple[str, str, int]:
    """Классификация ошибок при чтении данных."""
    kb_read = math.ceil(bytes_read / 1024)
    full_text = _collect_error_text(error)
    err_errno = _get_errno_from_chain(error)

    is_tcp16_20_range = TCP_BLOCK_MIN_KB <= kb_read <= TCP_BLOCK_MAX_KB

    # ConnectionResetError
    if _find_cause_of_type(error, ConnectionResetError) is not None \
       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
       or "connection reset" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"RST at {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI RESET[/bold red]", f"RST at {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]TCP RST[/bold red]", "RST before data", bytes_read)

    # ConnectionAbortedError
    if _find_cause_of_type(error, ConnectionAbortedError) is not None \
       or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED) \
       or "connection aborted" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Abort at {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI ABORT[/bold red]", f"Abort at {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]TCP ABORT[/bold red]", "Abort before data", bytes_read)

    # BrokenPipeError
    if _find_cause_of_type(error, BrokenPipeError) is not None \
       or err_errno == errno.EPIPE \
       or "broken pipe" in full_text:
        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Pipe broken {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI PIPE[/bold red]", f"Pipe {kb_read:.1f}KB", bytes_read)
        else:
            return ("[bold red]BROKEN PIPE[/bold red]", "Pipe broken", bytes_read)

    # RemoteProtocolError
    if isinstance(error, httpx.RemoteProtocolError) or "remoteprotocolerror" in full_text:
        if "peer closed" in full_text or "connection closed" in full_text:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"FIN at {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI CLOSE[/bold red]", f"Closed at {kb_read:.1f}KB", bytes_read)
            else:
                return ("[bold red]PEER CLOSE[/bold red]", "Closed early", bytes_read)
        elif "incomplete" in full_text:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"Incomplete {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI TRUNC[/bold red]", f"Truncated {kb_read:.1f}KB", bytes_read)
            else:
                return ("[bold red]INCOMPLETE[/bold red]", "Incomplete response", bytes_read)
        else:
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"Proto err {kb_read:.1f}KB", bytes_read)
            elif kb_read > 0:
                return ("[bold red]DPI PROTO[/bold red]", f"Proto err {kb_read:.1f}KB", bytes_read)
            else:
                return ("[red]PROTO ERR[/red]", "Protocol error", bytes_read)

    # httpx.ReadError
    if isinstance(error, httpx.ReadError):
        ssl_err = _find_cause_of_type(error, ssl.SSLError)
        if ssl_err is not None:
            label, detail, _ = _classify_ssl_error(ssl_err, bytes_read)
            if is_tcp16_20_range:
                return ("[bold red]TCP16-20[/bold red]", f"TLS err {kb_read:.1f}KB", bytes_read)
            return (label, f"{detail} at {kb_read:.1f}KB" if kb_read > 0 else detail, bytes_read)

        if is_tcp16_20_range:
            return ("[bold red]TCP16-20[/bold red]", f"Read err {kb_read:.1f}KB", bytes_read)
        elif kb_read > 0:
            return ("[bold red]DPI RESET[/bold red]", f"Read err {kb_read:.1f}KB", bytes_read)
        else:
            return ("[red]READ ERR[/red]", "Read error", bytes_read)

    # Fallback
    if is_tcp16_20_range:
        return ("[bold red]TCP16-20[/bold red]", f"Error at {kb_read:.1f}KB", bytes_read)
    elif kb_read > 0:
        return ("[bold red]DPI RESET[/bold red]", f"Error at {kb_read:.1f}KB", bytes_read)
    else:
        return ("[red]READ ERR[/red]", f"{type(error).__name__}", bytes_read)


# ============================================================================ Проверка TCP/TLS

async def check_tcp_tls_single(
    domain: str, tls_version: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, int, float]:
    """Одиночная проверка TCP/TLS."""
    bytes_read = 0

    async with semaphore:
        start_time = time.time()  # Засекаем время ПОСЛЕ семафора, внутри запроса

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if tls_version == "TLSv1.2":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif tls_version == "TLSv1.3":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        transport = httpx.AsyncHTTPTransport(verify=ctx, http2=False, retries=0)

        try:
            async with httpx.AsyncClient(
                transport=transport, timeout=TIMEOUT, follow_redirects=False
            ) as client:
                try:
                    req = client.build_request(
                        "GET",
                        f"https://{domain}",
                        headers={
                            "User-Agent": USER_AGENT,
                            "Accept-Encoding": "identity", # Отключаем сжатие
                            "Connection": "close"
                        }
                    )
                    response = await client.send(req, stream=True)
                    status_code = response.status_code
                    location = response.headers.get("location", "")

                    # HTTP 451 - официальная блокировка
                    if status_code == 451:
                        await response.aclose()
                        elapsed = time.time() - start_time
                        return ("[bold red]BLOCKED[/bold red]", "HTTP 451", bytes_read, elapsed)

                    # Умная проверка редиректов
                    if location:
                        location_lower = location.lower()

                        # Явные маркеры блок-страниц
                        if any(marker in location_lower for marker in BLOCK_MARKERS):
                            await response.aclose()
                            elapsed = time.time() - start_time
                            return ("[bold red]ISP PAGE[/bold red]", "Редирект на блок-страницу", bytes_read, elapsed)

                        # Проверяем домен редиректа
                        try:
                            parsed_location = urlparse(location if location.startswith('http') else f'https://{location}')
                            location_domain = parsed_location.netloc.lower()

                            clean_domain = domain.lower().replace('www.', '')
                            clean_location = location_domain.replace('www.', '')

                            # Редирект на другой домен (не поддомен)
                            if location_domain and clean_location != clean_domain and not clean_location.endswith('.' + clean_domain):
                                # Исключения: CDN, авторизация
                                legitimate_patterns = [
                                    'cloudflare', 'akamai', 'fastly', 'cdn', 'cloudfront',
                                    'auth', 'login', 'accounts', 'id.', 'sso.',
                                ]

                                is_legitimate = any(pattern in clean_location for pattern in legitimate_patterns)

                                if not is_legitimate:
                                    await response.aclose()
                                    elapsed = time.time() - start_time
                                    return ("[bold red]ISP PAGE[/bold red]", f"→ {location_domain[:20]}", bytes_read, elapsed)
                        except Exception:
                            pass

                    # Редирект (это OK)
                    if 300 <= status_code < 400:
                        await response.aclose()
                        elapsed = time.time() - start_time
                        return ("[green]OK[/green]", "", bytes_read, elapsed)

                    # Получили заголовки - замеряем время и закрываем
                    # НЕ читаем тело для измерения времени
                    elapsed = time.time() - start_time

                    # Проверка тела на блок-страницу только для малых ответов
                    # Делаем это отдельным запросом, чтобы не влиять на время
                    if status_code == 200:
                        content_length = response.headers.get("content-length", "")
                        try:
                            content_len = int(content_length) if content_length else 0
                        except:
                            content_len = 0

                        # Проверяем только если размер маленький (возможная блок-страница)
                        if content_len > 0 and content_len < BODY_INSPECT_LIMIT:
                            body_bytes = b""
                            try:
                                async for chunk in response.aiter_bytes(chunk_size=128):
                                    body_bytes += chunk
                                    if len(body_bytes) >= BODY_INSPECT_LIMIT:
                                        break
                            except Exception:
                                pass

                            body_text = body_bytes.decode("utf-8", errors="ignore").lower()
                            if any(m in body_text for m in BODY_BLOCK_MARKERS):
                                await response.aclose()
                                return ("[bold red]ISP PAGE[/bold red]", "Блок-страница в теле", len(body_bytes), elapsed)

                    await response.aclose()

                    # Любой HTTP 2xx-4xx - это OK
                    if 200 <= status_code < 500:
                        return ("[green]OK[/green]", "", bytes_read, elapsed)
                    else:
                        return ("[green]OK[/green]", f"HTTP {status_code}", bytes_read, elapsed)

                except httpx.ConnectTimeout:
                    elapsed = time.time() - start_time
                    return ("[red]TIMEOUT[/red]", "Таймаут handshake", bytes_read, elapsed)

                except httpx.ConnectError as e:
                    label, detail, br = _classify_connect_error(e, bytes_read)
                    elapsed = time.time() - start_time
                    return (label, detail, br, elapsed)

                except httpx.ReadTimeout:
                    kb_read = math.ceil(bytes_read / 1024)
                    elapsed = time.time() - start_time
                    if TCP_BLOCK_MIN_KB <= kb_read <= TCP_BLOCK_MAX_KB:
                        return ("[bold red]TCP16-20[/bold red]", f"Timeout {kb_read:.1f}KB", bytes_read, elapsed)
                    if kb_read > 0:
                        return ("[red]TIMEOUT[/red]", f"Read timeout {kb_read:.1f}KB", bytes_read, elapsed)
                    return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read, elapsed)

        except ssl.SSLError as e:
            label, detail, br = _classify_ssl_error(e, bytes_read)
            elapsed = time.time() - start_time
            return (label, detail, br, elapsed)

        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            label, detail, br = _classify_read_error(e, bytes_read)
            elapsed = time.time() - start_time
            return (label, detail, br, elapsed)

        except OSError as e:
            elapsed = time.time() - start_time
            err_num = e.errno
            if err_num in (errno.ECONNRESET, WSAECONNRESET):
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read, elapsed)
            elif err_num in (errno.ECONNREFUSED, WSAECONNREFUSED):
                return ("[bold red]REFUSED[/bold red]", "OS conn refused", bytes_read, elapsed)
            elif err_num in (errno.ETIMEDOUT, WSAETIMEDOUT):
                return ("[red]TIMEOUT[/red]", "OS timeout", bytes_read, elapsed)
            else:
                return ("[red]OS ERR[/red]", f"errno={err_num}", bytes_read, elapsed)

        except Exception as e:
            elapsed = time.time() - start_time
            return ("[red]ERR[/red]", f"{type(e).__name__}", bytes_read, elapsed)


async def check_tcp_tls(
    domain: str, tls_version: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, float]:
    """Множественная проверка TCP/TLS."""
    results = []

    for attempt in range(DOMAIN_CHECK_RETRIES):
        status, detail, bytes_read, elapsed = await check_tcp_tls_single(
            domain, tls_version, semaphore
        )
        results.append((status, detail, bytes_read, elapsed))

        if attempt < DOMAIN_CHECK_RETRIES - 1:
            await asyncio.sleep(0.1)

    # Приоритет критическим ошибкам
    critical_markers = [
        "TCP16-20", "DPI RESET", "DPI ABORT", "DPI CLOSE", "ISP PAGE",
        "BLOCKED", "TCP RST", "TCP ABORT", "TLS MITM", "TLS DPI", "TLS BLOCK",
    ]
    for status, detail, _, elapsed in results:
        if any(marker in status for marker in critical_markers):
            return (status, detail, elapsed)

    # Любые другие не-OK
    for status, detail, _, elapsed in results:
        if "OK" not in status:
            return (status, detail, elapsed)

    return (results[0][0], results[0][1], results[0][3])


# ============================================================================ Проверка HTTP Injection

async def check_http_injection(
    domain: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str]:
    """Проверка HTTP-инжекции."""
    async with semaphore:
        try:
            clean_domain = domain.replace("https://", "").replace("http://", "")

            async with httpx.AsyncClient(
                timeout=TIMEOUT, follow_redirects=False
            ) as client:
                req = client.build_request(
                    "GET",
                    f"http://{clean_domain}",
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept-Encoding": "identity", # Отключаем сжатие
                        "Connection": "close"
                    }
                )
                response = await client.send(req, stream=True)
                status_code = response.status_code
                location = response.headers.get("location", "")

                if status_code == 451:
                    await response.aclose()
                    return ("[bold red]BLOCKED[/bold red]", "HTTP 451")

                if any(marker in location.lower() for marker in BLOCK_MARKERS):
                    await response.aclose()
                    return ("[bold red]ISP PAGE[/bold red]", "Блок-страница")

                # Проверка тела для 200 OK
                if 200 <= status_code < 300:
                    body_bytes = b""
                    try:
                        async for chunk in response.aiter_bytes(chunk_size=128):
                            body_bytes += chunk
                            if len(body_bytes) >= BODY_INSPECT_LIMIT:
                                break
                    except Exception:
                        pass
                    await response.aclose()

                    body_text = body_bytes.decode("utf-8", errors="ignore").lower()
                    if any(m in body_text for m in BODY_BLOCK_MARKERS):
                        return ("[bold red]ISP PAGE[/bold red]", "Блок-страница (HTTP)")
                    return ("[green]OK[/green]", f"{status_code}")

                # Редирект - OK
                if 300 <= status_code < 400:
                    await response.aclose()
                    return ("[green]REDIR[/green]", f"{status_code}")

                await response.aclose()
                return ("[green]OK[/green]", f"{status_code}")

        except httpx.ConnectTimeout:
            return ("[red]TIMEOUT[/red]", "Timeout")

        except httpx.ConnectError as e:
            full_text = _collect_error_text(e)
            if _find_cause_of_type(e, socket.gaierror) is not None \
               or any(x in full_text for x in ["getaddrinfo", "name resolution"]):
                return ("[yellow]DNS FAIL[/yellow]", "DNS error")
            if _find_cause_of_type(e, ConnectionRefusedError) is not None \
               or "refused" in full_text:
                return ("[red]REFUSED[/red]", "Refused")
            if _find_cause_of_type(e, ConnectionResetError) is not None \
               or "reset" in full_text:
                return ("[red]TCP RST[/red]", "RST")
            if _find_cause_of_type(e, TimeoutError) is not None \
               or "timed out" in full_text:
                return ("[red]TIMEOUT[/red]", "Timeout")
            return ("[red]CONN ERR[/red]", "Conn error")

        except Exception as e:
            return ("[red]HTTP ERR[/red]", f"{type(e).__name__}")


# ============================================================================ Проверка TCP 16-20KB блока

async def check_tcp_16_20_single(
    url: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str, int]:
    """Одиночная проверка TCP 16-20KB лимита."""
    bytes_read = 0

    async with semaphore:
        start_time = time.time()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        transport = httpx.AsyncHTTPTransport(verify=ctx, http2=False, retries=0)

        try:
            async with httpx.AsyncClient(
                transport=transport, timeout=TIMEOUT_TCP_16_20, follow_redirects=False
            ) as client:
                req = client.build_request(
                    "GET",
                    url,
                    headers={
                        "User-Agent": USER_AGENT,
                        "Accept-Encoding": "identity", # Отключаем сжатие
                        "Connection": "close"
                    }
                )
                response = await client.send(req, stream=True)

                try:
                    async for chunk in response.aiter_bytes(chunk_size=128):
                        bytes_read += len(chunk)
                        if bytes_read >= DATA_READ_THRESHOLD:
                            await response.aclose()
                            elapsed = time.time() - start_time
                            return (
                                "[green]OK[/green]",
                                f"Complete ({elapsed:.1f}s)",
                                bytes_read,
                            )

                    await response.aclose()
                    elapsed = time.time() - start_time
                    return (
                        "[green]OK[/green]",
                        f"Complete ({elapsed:.1f}s)",
                        bytes_read,
                    )

                except (
                    httpx.ReadError,
                    httpx.RemoteProtocolError,
                    ConnectionResetError,
                    ConnectionAbortedError,
                    BrokenPipeError,
                ) as e:
                    kb_read = math.ceil(bytes_read / 1024)
                    full_text = _collect_error_text(e)
                    err_errno = _get_errno_from_chain(e)

                    if _find_cause_of_type(e, ConnectionResetError) is not None \
                       or err_errno in (errno.ECONNRESET, WSAECONNRESET) \
                       or "connection reset" in full_text:
                        error_detail = "RST by peer"
                    elif _find_cause_of_type(e, ConnectionAbortedError) is not None \
                         or err_errno in (getattr(errno, 'ECONNABORTED', 103), WSAECONNABORTED):
                        error_detail = "Connection aborted"
                    elif _find_cause_of_type(e, BrokenPipeError) is not None \
                         or err_errno == errno.EPIPE:
                        error_detail = "Broken pipe"
                    elif isinstance(e, httpx.RemoteProtocolError):
                        if "peer closed" in full_text:
                            error_detail = "Peer sent FIN"
                        elif "incomplete" in full_text:
                            error_detail = "Incomplete response"
                        else:
                            error_detail = "Protocol error"
                    else:
                        ssl_err = _find_cause_of_type(e, ssl.SSLError)
                        if ssl_err is not None:
                            _, ssl_detail, _ = _classify_ssl_error(ssl_err, bytes_read)
                            error_detail = f"TLS: {ssl_detail}"
                        else:
                            error_detail = _clean_detail(str(e)[:50])

                    if kb_read > 0:
                        return (
                            "[bold red]DETECTED[/bold red]",
                            f"Dropped at {kb_read:.0f}KB — {error_detail}",
                            bytes_read,
                        )
                    else:
                        return (
                            "[red]CONN ERR[/red]",
                            f"Failed: {error_detail}",
                            bytes_read,
                        )

        except httpx.ConnectTimeout:
            return ("[red]TIMEOUT[/red]", "Handshake timeout", bytes_read)

        except httpx.ConnectError as e:
            status, detail, br = _classify_connect_error(e, bytes_read)
            return (status, detail, br)

        except httpx.ReadTimeout:
            kb_read = math.ceil(bytes_read / 1024)
            if kb_read > 0:
                return (
                    "[bold red]DETECTED[/bold red]",
                    f"Read timeout at {kb_read:.0f}KB",
                    bytes_read,
                )
            return ("[red]TIMEOUT[/red]", "Read timeout", bytes_read)

        except ssl.SSLError as e:
            label, detail, br = _classify_ssl_error(e, bytes_read)
            return (label, detail, br)

        except OSError as e:
            kb_read = math.ceil(bytes_read / 1024)
            err_num = e.errno
            if err_num in (errno.ECONNRESET, WSAECONNRESET):
                if kb_read > 0:
                    return (
                        "[bold red]DETECTED[/bold red]",
                        f"OS conn reset at {kb_read:.0f}KB",
                        bytes_read,
                    )
                return ("[bold red]TCP RST[/bold red]", "OS conn reset", bytes_read)
            else:
                return ("[red]OS ERR[/red]", f"errno={err_num}", bytes_read)

        except Exception as e:
            kb_read = math.ceil(bytes_read / 1024)
            error_detail = f"{type(e).__name__}"
            if kb_read > 0:
                return (
                    "[red]ERROR[/red]",
                    f"Error at {kb_read:.0f}KB — {error_detail}",
                    bytes_read,
                )
            return ("[red]ERROR[/red]", error_detail, bytes_read)


async def check_tcp_16_20(
    url: str, semaphore: asyncio.Semaphore
) -> Tuple[str, str]:
    """Проверка TCP 16-20KB лимита с множественными попытками."""
    results = []

    for attempt in range(TCP_16_20_CHECK_RETRIES):
        status, detail, bytes_read = await check_tcp_16_20_single(url, semaphore)
        results.append((status, detail, bytes_read))

        if attempt < TCP_16_20_CHECK_RETRIES - 1:
            await asyncio.sleep(0.1)

    # Приоритизируем ошибки
    for status, detail, _ in results:
        if "DETECTED" in status:
            return (status, detail)

    for status, detail, _ in results:
        if "OK" not in status:
            return (status, detail)

    # Проверка на балансировку DPI стратегий
    if TCP_16_20_CHECK_RETRIES > 1:
        ok_count = sum(1 for s, _, _ in results if "OK" in s)
        error_count = len(results) - ok_count

        if ok_count > 0 and error_count > 0:
            variance_percent = (error_count / len(results)) * 100
            if variance_percent >= DPI_VARIANCE_THRESHOLD:
                return (
                    "[bold yellow]MIXED RESULTS[/bold yellow]",
                    f"{ok_count} OK, {error_count} blocked — возможная балансировка DPI",
                )

    return (results[0][0], results[0][1])


# ============================================================================ Worker функции

async def worker(domain, semaphore: asyncio.Semaphore):
    results = await asyncio.gather(
        check_tcp_tls(domain, "TLSv1.2", semaphore),
        check_tcp_tls(domain, "TLSv1.3", semaphore),
        check_http_injection(domain, semaphore),
        return_exceptions=True,
    )

    t12_status, t12_detail, t12_elapsed = (
        results[0]
        if not isinstance(results[0], Exception)
        else ("[dim]ERR[/dim]", f"{type(results[0]).__name__}", 0.0)
    )
    t13_status, t13_detail, t13_elapsed = (
        results[1]
        if not isinstance(results[1], Exception)
        else ("[dim]ERR[/dim]", f"{type(results[1]).__name__}", 0.0)
    )
    http_status, http_detail = (
        results[2]
        if not isinstance(results[2], Exception)
        else ("[dim]ERR[/dim]", f"{type(results[2]).__name__}")
    )

    # Если TLS 1.2 работает, а 1.3 выдает TLS DPI - это несовместимость
    if "OK" in t12_status and "TLS DPI" in t13_status:
        t13_detail = "TLS1.3 unsupported"

    details = []
    d12 = _clean_detail(t12_detail)
    d13 = _clean_detail(t13_detail)

    # Показываем ТОЛЬКО время TLS 1.3 запроса (чистое время одного запроса)
    request_time = t13_elapsed

    if d12 or d13:
        if d12 == d13:
            details.append(d12)
        else:
            if d12:
                details.append(f"T12:{d12}")
            if d13:
                details.append(f"T13:{d13}")

        # Показываем время для ошибок
        if request_time > 0:
            details.append(f"{request_time:.1f}s")
    elif "OK" in t12_status or "OK" in t13_status:
        # Для OK показываем время TLS 1.3 запроса
        if request_time > 0:
            details.append(f"{request_time:.1f}s")

    detail_str = " | ".join([d for d in details if d])

    return [domain, t12_status, t13_status, http_status, detail_str]


async def tcp_16_20_worker(item: dict, semaphore: asyncio.Semaphore):
    status, error_detail = await check_tcp_16_20(item["url"], semaphore)
    return [item["id"], item["provider"], status, error_detail]


# ============================================================================ Main функция

async def main():
    console.clear()
    console.print(
        "[bold cyan]🇷🇺 Russian DPI Checker[/bold cyan] | "
        "[yellow]TCP/TLS + HTTP + TCP 16-20KB Test[/yellow]"
    )
    console.print(
        f"Тестирование {len(DOMAINS)} доменов + {len(TCP_16_20_ITEMS)} TCP 16-20KB целей."
    )
    console.print(
        f"[dim]Таймаут: {TIMEOUT}s (домены), {TIMEOUT_TCP_16_20}s (TCP 16-20KB) | "
        f"Потоков: {MAX_CONCURRENT}[/dim]"
    )
    console.print(
        f"[dim]Попыток: {DOMAIN_CHECK_RETRIES}x (домены), "
        f"{TCP_16_20_CHECK_RETRIES}x (TCP 16-20KB)[/dim]"
    )
    console.print(
        f"[dim]Порог вариативности DPI: {DPI_VARIANCE_THRESHOLD}% | "
        f"Диапазон TCP блока: {TCP_BLOCK_MIN_KB}-{TCP_BLOCK_MAX_KB}KB[/dim]\n"
        f"[dim]Только IPv4: {USE_IPV4_ONLY}\n"
    )

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    console.print(
        "[bold]Часть 1: Проверка доменов (TLS + HTTP injection)[/bold]\n"
    )

    table = Table(
        show_header=True, header_style="bold magenta", border_style="dim"
    )
    table.add_column("Домен", style="cyan", no_wrap=True, width=18)
    table.add_column("TLS1.2", justify="center", width=11)
    table.add_column("TLS1.3", justify="center", width=11)
    table.add_column("HTTP", justify="center", width=10)
    table.add_column("Детали", style="dim", no_wrap=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task("Проверка доменов...", total=len(DOMAINS))
        tasks = [worker(d, semaphore) for d in DOMAINS]

        results = []
        completed = 0
        for future in asyncio.as_completed(tasks):
            res = await future
            results.append(res)
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Проверка доменов ({completed}/{len(DOMAINS)})...",
            )

    results.sort(key=lambda x: x[0])

    for r in results:
        table.add_row(*r)

    console.print(table)

    # === TCP 16-20KB проверка ===
    console.print("\n[bold]Часть 2: Проверка TCP 16-20KB блока[/bold]")
    console.print(
        "[dim]Тестирование обрыва соединения при передаче данных (На самом деле 14-32KB блокировка)[/dim]\n"
    )

    tcp_table = Table(
        show_header=True, header_style="bold magenta", border_style="dim"
    )
    tcp_table.add_column("ID", style="white", width=14)
    tcp_table.add_column("Провайдер", style="cyan", width=18)
    tcp_table.add_column("Статус", justify="center", width=16)
    tcp_table.add_column("Ошибка / Детали", style="dim")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            "Проверка TCP 16-20KB...", total=len(TCP_16_20_ITEMS)
        )
        tasks = [tcp_16_20_worker(item, semaphore) for item in TCP_16_20_ITEMS]

        tcp_results = []
        completed = 0
        for future in asyncio.as_completed(tasks):
            res = await future
            tcp_results.append(res)
            completed += 1
            progress.update(
                task_id,
                completed=completed,
                description=f"Проверка TCP 16-20KB ({completed}/{len(TCP_16_20_ITEMS)})...",
            )

    # Сортируем по провайдеру (убираем эмодзи для правильной сортировки)
    def sort_key(row):
        provider = row[1]
        clean_provider = re.sub(r'[^\w\s]', '', provider).strip()
        return (clean_provider, row[0])

    tcp_results.sort(key=sort_key)

    passed = sum(1 for r in tcp_results if "OK" in r[2])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[2])
    mixed = sum(1 for r in tcp_results if "MIXED RESULTS" in r[2])

    for r in tcp_results:
        tcp_table.add_row(*r)

    console.print(tcp_table)

    console.print(
        f"\n[bold]Результаты TCP 16-20KB:[/bold] "
        f"OK {passed}/{len(TCP_16_20_ITEMS)}",
        end="",
    )
    if blocked > 0:
        console.print(f" / {blocked} обнаружено", end="")
    if mixed > 0:
        console.print(f" / {mixed} смешанных", end="")
    console.print()

    # Статистика первого теста
    ok_count = sum(1 for r in results if "OK" in r[1] or "OK" in r[2])

    console.print(
        f"[bold]Результаты проверки доменов:[/bold] "
        f"OK {ok_count}/{len(DOMAINS)}"
    )

    if mixed > 0:
        console.print(
            f"[bold yellow]⚠ ОБНАРУЖЕНА БАЛАНСИРОВКА:[/bold yellow] "
            f"{mixed} цель(ей) показали непоследовательные результаты"
        )
        console.print(
            "[dim]Это указывает на то, что провайдер может использовать "
            "несколько DPI стратегий с балансировкой трафика[/dim]"
        )

    console.print("\n[bold]Легенда:[/bold]")
    legend = [
        ("ISP PAGE", "HTTP редирект или тело содержит блок-страницу провайдера"),
        ("BLOCKED", "HTTP 451 (Недоступно по юридическим причинам)"),
        ("TCP16-20", "Соединение оборвано после 14-32KB (блок передачи данных DPI)"),
        ("DETECTED", "Обнаружена блокировка при передаче данных"),
        ("TLS MITM", "Man-in-the-Middle атака (проблемы с сертификатом/шифром)"),
        ("TLS DPI", "DPI манипулирует TLS handshake или записями"),
        ("TLS BLOCK", "Блокировка версии TLS или downgrade"),
        ("DPI RESET", "Соединение сброшено при передаче данных"),
        ("TIMEOUT", "Таймаут соединения или чтения"),
        ("DNS FAIL", "Не удалось разрешить доменное имя"),
        ("REFUSED", "Соединение отклонено (порт закрыт/RST)"),
        ("OK / REDIR", "Сайт доступен (может редиректить)"),
    ]

    for term, desc in legend:
        console.print(f"[dim]• [cyan]{term:<12}[/cyan] = {desc}[/dim]")

    console.print("\n[bold green]Проверка завершена.[/bold green]")


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Прервано пользователем.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Критическая ошибка:[/bold red] {e}")
    finally:
        if sys.platform == 'win32':
            print("\nНажмите Enter для выхода...")
            input()