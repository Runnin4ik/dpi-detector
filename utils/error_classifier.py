import ssl
import math
import errno
import socket
from typing import Tuple, Optional

import httpx

from utils import config


# ── Утилиты для обхода цепочки исключений ────────────────────────────────────

def find_cause(exc: Exception, target_type: type, max_depth: int = 10) -> Optional[Exception]:
    """Возвращает первое исключение заданного типа из цепочки, или None."""
    current = exc
    for _ in range(max_depth):
        if isinstance(current, target_type):
            return current
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def get_errno_from_chain(exc: Exception, max_depth: int = 10) -> Optional[int]:
    current = exc
    for _ in range(max_depth):
        if isinstance(current, OSError) and current.errno is not None:
            return current.errno
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return None


def collect_error_text(exc: Exception, max_depth: int = 10) -> str:
    parts = []
    current = exc
    for _ in range(max_depth):
        parts.append(str(current).lower())
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            break
        current = nxt
    return " | ".join(parts)


# ── Форматирование деталей ────────────────────────────────────────────────────

def clean_detail(detail: str) -> str:
    import re
    if not detail or detail in ("OK", "Error"):
        return ""
    detail = detail.replace("The operation did not complete", "TLS Aborted")
    detail = re.sub(r"\s*\(_*\s*$", "", detail)
    detail = re.sub(r"\s+", " ", detail).strip()
    detail = detail.replace("Err None: ", "").replace("Conn failed: ", "")
    if re.match(r"^HTTP [23]\d\d$", detail):
        return ""
    return detail.strip()


# ── Классификаторы ошибок ─────────────────────────────────────────────────────

def classify_ssl_error(error: ssl.SSLError, bytes_read: int) -> Tuple[str, str, int]:
    msg = str(error).lower()

    # DPI: обрыв handshake / передачи данных
    dpi_interruption = [
        "eof", "unexpected eof", "eof occurred in violation",
        "operation did not complete", "bad record mac",
        "decryption failed", "decrypt"
    ]
    if any(m in msg for m in dpi_interruption):
        detail = "Обрыв при передаче" if bytes_read > 0 else "Handshake aborted"
        return ("[bold red]TLS DPI[/bold red]", detail, bytes_read)

    # DPI: манипуляции с handshake
    if any(x in msg for x in [
        "illegal parameter", "decode error", "decoding error",
        "record overflow", "oversized",
        "record layer failure", "record_layer_failure",
        "bad key share", "bad_key_share"
    ]):
        if "bad key share" in msg or "bad_key_share" in msg:
            return ("[yellow]SSL ERR[/yellow]", "Bad key share", bytes_read)
        if "record layer failure" in msg or "record_layer_failure" in msg:
            return ("[yellow]SSL ERR[/yellow]", "Record layer fail", bytes_read)
        return ("[bold red]TLS DPI[/bold red]", "Подмена handshake", bytes_read)

    if "unrecognized name" in msg or "unrecognized_name" in msg:
        return ("[bold red]TLS DPI[/bold red]", "SNI блок", bytes_read)

    if "alert handshake" in msg or "sslv3_alert_handshake" in msg:
        return ("[bold red]TLS DPI[/bold red]", "Handshake alert", bytes_read)

    if "handshake" in msg:
        if "unexpected" in msg:
            return ("[bold red]TLS DPI[/bold red]", "HS подмена", bytes_read)
        elif "failure" in msg:
            return ("[bold red]TLS DPI[/bold red]", "HS failure", bytes_read)

    if "wrong version number" in msg:
        return ("[bold red]TLS DPI[/bold red]", "Non-TLS ответ", bytes_read)

    # MITM: проблемы с сертификатом
    if isinstance(error, ssl.SSLCertVerificationError):
        verify_code = getattr(error, 'verify_code', None)
        if verify_code == 10 or "expired" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        elif verify_code in (18, 19) or "self-signed" in msg or "self signed" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Self-signed cert", bytes_read)
        elif verify_code == 20 or "unknown ca" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif verify_code == 62 or "hostname mismatch" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Hostname mismatch", bytes_read)
        else:
            return ("[bold red]TLS MITM[/bold red]", "Cert fail", bytes_read)

    if "certificate" in msg:
        if "verify failed" in msg or "unknown ca" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Unknown CA", bytes_read)
        elif "hostname mismatch" in msg or "name mismatch" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert mismatch", bytes_read)
        elif "expired" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        else:
            return ("[red]SSL CERT[/red]", "Cert error", bytes_read)

    if "cipher" in msg or "no shared cipher" in msg:
        return ("[bold red]TLS MITM[/bold red]", "Cipher mismatch", bytes_read)

    if "version" in msg or "protocol version" in msg:
        return ("[bold red]BLOCK[/bold red]", "TLS version block", bytes_read)

    if isinstance(error, ssl.SSLZeroReturnError):
        # Close notify в неожиданный момент — признак DPI или блокировки
        return ("[bold red]TLS DPI[/bold red]", "Неожиданный close notify", bytes_read)

    if "internal error" in msg:
        return ("[red]SSL ERR[/red]", "Internal error", bytes_read)

    if "handshake" in msg:
        return ("[red]TLS ERR[/red]", "Handshake error", bytes_read)

    return ("[red]SSL ERR[/red]", clean_detail(str(error)[:40]), bytes_read)


def classify_connect_error(error: Exception, bytes_read: int) -> Tuple[str, str, int]:
    """Единая классификация ошибок установки соединения (L3/L4/DNS)."""
    full_text = collect_error_text(error)
    err_errno = get_errno_from_chain(error)

    if isinstance(error, httpx.PoolTimeout) or "pool timeout" in full_text:
        return ("[magenta]POOL TIMEOUT[/magenta]", "Нехватка сокетов, снизьте параллелизм", bytes_read)

    if isinstance(error, httpx.ConnectTimeout) or "connect timeout" in full_text:
        return ("[red]TIMEOUT[/red]", "TCP timeout (SYN Drop)", bytes_read)

    # DNS
    gai = find_cause(error, socket.gaierror)
    if gai is not None:
        gai_errno = getattr(gai, 'errno', None)
        if gai_errno in (socket.EAI_NONAME, 11001):
            return ("[yellow]DNS FAIL[/yellow]", "Домен не найден", bytes_read)
        elif gai_errno in (getattr(socket, 'EAI_AGAIN', -3), 11002):
            if "connection" in full_text and any(x in full_text for x in ("reset", "refused", "closed")):
                return ("[yellow]DNS FAIL[/yellow]", "DNS ошибка/дроп", bytes_read)
            return ("[yellow]DNS FAIL[/yellow]", "DNS таймаут/недоступен", bytes_read)
        else:
            return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    if any(x in full_text for x in [
        "getaddrinfo failed", "name resolution", "11001", "11002",
        "name or service not known", "nodename nor servname"
    ]):
        return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    # TLS ALERT внутри ConnectError (DPI)
    if "sslv3_alert" in full_text or "ssl alert" in full_text or ("alert" in full_text and "handshake" in full_text):
        if "handshake_failure" in full_text or "handshake failure" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "Handshake alert", bytes_read)
        elif "unrecognized_name" in full_text:
            return ("[bold red]TLS DPI[/bold red]", "SNI alert", bytes_read)
        elif "protocol_version" in full_text or "alert_protocol_version" in full_text:
            return ("[bold red]TLS BLOCK[/bold red]", "Version alert", bytes_read)
        else:
            return ("[bold red]TLS DPI[/bold red]", "TLS alert", bytes_read)

    ssl_err = find_cause(error, ssl.SSLError)
    if ssl_err is not None:
        return classify_ssl_error(ssl_err, bytes_read)

    # TCP ОШИБКИ (L4)
    if find_cause(error, ConnectionRefusedError) is not None or err_errno in (errno.ECONNREFUSED, config.WSAECONNREFUSED) or "refused" in full_text:
        return ("[bold red]REFUSED[/bold red]", "TCP соединение отклонено", bytes_read)

    if find_cause(error, ConnectionResetError) is not None or err_errno in (errno.ECONNRESET, config.WSAECONNRESET) or "connection reset" in full_text:
        return ("[bold red]RST[/bold red]", "TCP соединение сброшено", bytes_read)

    if find_cause(error, ConnectionAbortedError) is not None or err_errno in (getattr(errno, 'ECONNABORTED', 103), config.WSAECONNABORTED) or "connection aborted" in full_text:
        return ("[bold red]ABORT[/bold red]", "TCP соединение прервано", bytes_read)

    if find_cause(error, TimeoutError) is not None or err_errno in (errno.ETIMEDOUT, config.WSAETIMEDOUT) or "timed out" in full_text:
        return ("[red]TIMEOUT[/red]", "TCP timeout (SYN Drop)", bytes_read)

    if err_errno in (errno.ENETUNREACH, config.WSAENETUNREACH) or "network is unreachable" in full_text:
        return ("[red]NET UNREACH[/red]", "Нет маршрута (ICMP unreach)", bytes_read)

    if err_errno in (errno.EHOSTUNREACH, config.WSAEHOSTUNREACH) or "no route to host" in full_text:
        return ("[red]HOST UNREACH[/red]", "Нет маршрута до хоста", bytes_read)

    if "all connection attempts failed" in full_text:
        return ("[bold red]REFUSED[/bold red]", "TCP соединение отклонено", bytes_read)

    return ("[red]CONN ERR[/red]", clean_detail(str(error)[:40]), bytes_read)


def classify_read_error(error: Exception, bytes_read: int) -> Tuple[str, str, int]:
    full_text = collect_error_text(error)
    err_errno = get_errno_from_chain(error)

    if find_cause(error, ConnectionResetError) is not None \
            or err_errno in (errno.ECONNRESET, config.WSAECONNRESET) \
            or "connection reset" in full_text:
        return ("[bold red]RST[/bold red]", "TCP соединение сброшено", bytes_read)

    if find_cause(error, ConnectionAbortedError) is not None \
            or err_errno in (getattr(errno, 'ECONNABORTED', 103), config.WSAECONNABORTED) \
            or "connection aborted" in full_text:
        return ("[bold red]ABORT[/bold red]", "TCP соединение прервано", bytes_read)

    if find_cause(error, BrokenPipeError) is not None \
            or err_errno == errno.EPIPE \
            or "broken pipe" in full_text:
        return ("[bold red]RST[/bold red]", "Broken pipe", bytes_read)

    if isinstance(error, httpx.RemoteProtocolError) or "remoteprotocolerror" in full_text:
        if "peer closed" in full_text or "connection closed" in full_text:
            return ("[bold red]ABORT[/bold red]", "Closed early", bytes_read)
        elif "incomplete" in full_text:
            return ("[bold red]ABORT[/bold red]", "Incomplete response", bytes_read)
        else:
            return ("[red]PROTO ERR[/red]", "Protocol error", bytes_read)

    if isinstance(error, httpx.ReadError):
        ssl_err = find_cause(error, ssl.SSLError)
        if ssl_err is not None:
            return classify_ssl_error(ssl_err, bytes_read)
        return ("[red]READ ERR[/red]", "Read error", bytes_read)

    return ("[red]READ ERR[/red]", f"{type(error).__name__}", bytes_read)