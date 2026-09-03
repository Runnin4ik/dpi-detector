import ssl
import errno
import socket
import asyncio
from typing import Tuple, Optional
from enum import Enum


class ProbeStatus(str, Enum):
    OK = "OK"
    REDIR = "REDIR"
    BLOCKED = "BLOCKED"
    ISP_PAGE = "ISP PAGE"
    LOCAL_IP = "LOCAL IP"
    TIMEOUT = "TIMEOUT"
    TCP16_20 = "TCP16-20"
    TLS_RST = "TLS RST"
    TLS_ALERT = "TLS ALERT"
    TLS_BLOCK = "TLS BLOCK"
    TLS_MITM = "TLS MITM"
    NO_CA = "NO CA BUNDLE"
    TLS_SPOOF = "TLS SPOOF"
    TLS_EOF = "TLS EOF"
    NO_TLS13 = "NO TLS1.3"
    DNS_FAIL = "DNS FAIL"
    OS_ERR = "OS ERR"
    ERR = "ERR"

    @classmethod
    def is_ok(cls, status_str: str) -> bool:
        """Проверяет, считается ли статус успехом (зелёный OK или легитимный редирект)."""
        if not status_str:
            return False
        import re
        plain = re.sub(r"\[.*?\]", "", status_str).strip().upper()
        if "REDIR_SUSPECT" in status_str or "BLOCKED" in plain:
            return False
        if "[red]" in status_str or "[bold red]" in status_str:
            return False
        if "[green]" in status_str:
            return True
        return plain in (cls.OK.value, cls.REDIR.value) or plain.startswith(("OK", "REDIR"))

    @classmethod
    def is_blocked(cls, status_str: str) -> bool:
        if not status_str:
            return False
        import re
        plain = re.sub(r"\[.*?\]", "", status_str).strip().upper()
        block_markers = (
            cls.BLOCKED.value, cls.ISP_PAGE.value, cls.TCP16_20.value,
            cls.TLS_RST.value, cls.TLS_ALERT.value, cls.TLS_BLOCK.value,
            cls.TLS_MITM.value, cls.TLS_SPOOF.value, cls.TLS_EOF.value,
            "TLS DPI", "TCP RST", "TCP ABORT"
        )
        return any(m in plain for m in block_markers)
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


def is_timeout_error(exc: Exception) -> bool:
    """True для TimeoutError и asyncio.TimeoutError — до Python 3.11 это
    разные классы, поэтому классификатор иначе не видит таймауты
    asyncio (например, asyncio.wait_for у TCP-коннекта DoT)."""
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return True
    return (find_cause(exc, TimeoutError) is not None
            or find_cause(exc, asyncio.TimeoutError) is not None)


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

def classify_ssl_error(error: ssl.SSLError, bytes_read: int, stage: str = "unknown") -> Tuple[str, str, int]:
    msg = str(error).lower()
    full_text = collect_error_text(error)

    if "pop from an empty deque" in full_text or "brokenresourceerror" in full_text:
        return ("[bold red]TLS RST[/bold red]", "TCP RST на ClientHello", bytes_read)

    if "wrong version number" in msg or "wrong_version_number" in msg:
        return ("[bold red]TLS SPOOF[/bold red]", "Подмена ответа (Wrong Version)", bytes_read)
    if any(x in msg for x in ["record overflow", "oversized", "record layer failure", "decode error", "decoding error", "illegal parameter"]):
        return ("[bold red]TLS SPOOF[/bold red]", "Подмена ответа (Garbage Data)", bytes_read)

    if "alert" in msg:
        if "unrecognized_name" in msg or "unrecognized name" in msg:
            return ("[bold red]TLS ALERT[/bold red]", "SNI Block (Unrecognized Name)", bytes_read)
        if "handshake_failure" in msg or "handshake failure" in msg:
            return ("[bold red]TLS ALERT[/bold red]", "DPI Alert (Handshake Failure)", bytes_read)
        if "protocol_version" in msg:
            # Если мы проверяем TLS 1.3, а прилетает этот алерт - возможно, блок версии
            return ("[bold red]TLS BLOCK[/bold red]", "Protocol Version Alert", bytes_read)
        return ("[bold red]TLS ALERT[/bold red]", "Поддельный TLS Alert", bytes_read)

    dpi_interruption = ["eof", "unexpected eof", "eof occurred", "operation did not complete", "want_read"]
    if any(m in msg for m in dpi_interruption):
        # Если это произошло во время хендшейка - в 99% это активный RST, замаскированный ОС под EOF
        if bytes_read == 0 or stage == "tls_handshake":
            return ("[bold red]TLS RST[/bold red]", "TCP RST на ClientHello", bytes_read)

        detail = "Обрыв при передаче (EOF)" if bytes_read > 0 else "Тихий обрыв (Handshake EOF)"
        return ("[bold red]TLS EOF[/bold red]", detail, bytes_read)

    if isinstance(error, ssl.SSLCertVerificationError) or "certificate" in msg or "unknown ca" in msg:
        verify_code = getattr(error, 'verify_code', None)
        if verify_code == 20 or "unable to get local issuer certificate" in msg:
            return ("[bold yellow]NO CA BUNDLE[/bold yellow]", "Отсутствуют корневые сертификаты", bytes_read)
        if verify_code == 10 or "expired" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Cert expired", bytes_read)
        if verify_code in (18, 19) or "self-signed" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Self-signed cert", bytes_read)
        if verify_code == 62 or "hostname mismatch" in msg:
            return ("[bold red]TLS MITM[/bold red]", "Hostname mismatch", bytes_read)
        return ("[bold red]TLS MITM[/bold red]", "Подмена сертификата", bytes_read)

    if "version" in msg or "protocol version" in msg:
        return ("[bold red]NO TLS1.3[/bold red]", "Server has no TLS 1.3", bytes_read)

    if "internal error" in msg:
        return ("[red]UNKNOWN[/red] [dim]SSL[/dim]", "Internal error", bytes_read)

    # Неизвестная SSL-ошибка: тип исключения в ярлыке, текст — в детали
    return (f"[red]UNKNOWN[/red] [dim]{type(error).__name__}[/dim]",
            clean_detail(str(error)[:40]), bytes_read)


def classify_connect_error(error: Exception, bytes_read: int, stage: str = "unknown") -> Tuple[str, str, int]:
    """Единая классификация ошибок установки соединения (L3/L4/DNS)."""
    full_text = collect_error_text(error)
    err_errno = get_errno_from_chain(error)

    if isinstance(error, httpx.PoolTimeout) or "pool timeout" in full_text:
        return ("[magenta]POOL TIMEOUT[/magenta]", "Нехватка сокетов, снизьте параллелизм", bytes_read)

    if isinstance(error, httpx.ConnectTimeout) or "connect timeout" in full_text or "timed out" in full_text:
        if stage == "tls_handshake":
            return ("[bold red]TLS DROP[/bold red]", "TLS Handshake timeout", bytes_read)
        if stage == "tcp_connect":
            return ("[bold red]SYN DROP[/bold red]", "TCP SYN timeout", bytes_read)
        if stage == "sending_data":
            return ("[red]SEND TIMEOUT[/red]", "Таймаут отправки данных", bytes_read)
        if stage == "reading_data":
            return ("[red]READ TIMEOUT[/red]", "Таймаут чтения данных", bytes_read)
        return ("[red]TIMEOUT[/red]", f"Timeout ({stage})", bytes_read)

    # DNS
    gai = find_cause(error, socket.gaierror)
    if gai is not None:
        gai_errno = getattr(gai, 'errno', None)
        if gai_errno in (socket.EAI_NONAME, 11001):
            return ("[yellow]DNS FAIL[/yellow]", "Домен не найден", bytes_read)
        if gai_errno in (getattr(socket, 'EAI_AGAIN', -3), 11002):
            if "connection" in full_text and any(x in full_text for x in ("reset", "refused", "closed")):
                return ("[yellow]DNS FAIL[/yellow]", "DNS ошибка/дроп", bytes_read)
            return ("[yellow]DNS FAIL[/yellow]", "DNS таймаут/недоступен", bytes_read)
        return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    if any(x in full_text for x in [
        "getaddrinfo failed", "name resolution", "11001", "11002",
        "name or service not known", "nodename nor servname"
    ]):
        return ("[yellow]DNS FAIL[/yellow]", "Ошибка DNS", bytes_read)

    # TLS ALERT внутри ConnectError (DPI)
    if "sslv3_alert" in full_text or "ssl alert" in full_text or ("alert" in full_text and "handshake" in full_text):
        if "handshake_failure" in full_text or "handshake failure" in full_text:
            return ("[bold red]TLS ALERT[/bold red]", "Handshake alert", bytes_read)
        if "unrecognized_name" in full_text:
            return ("[bold red]TLS ALERT[/bold red]", "SNI alert", bytes_read)
        if "protocol_version" in full_text or "alert_protocol_version" in full_text:
            return ("[bold red]TLS ALERT[/bold red]", "Version alert", bytes_read)
        return ("[bold red]TLS ALERT[/bold red]", "TLS alert", bytes_read)

    ssl_err = find_cause(error, ssl.SSLError)
    if ssl_err is not None:
        return classify_ssl_error(ssl_err, bytes_read, stage=stage)

    # TCP ОШИБКИ (L4)
    if find_cause(error, ConnectionRefusedError) is not None or err_errno in (errno.ECONNREFUSED, config.WSAECONNREFUSED) or "refused" in full_text:
        return ("[bold red]REFUSED[/bold red]", "TCP соединение отклонено", bytes_read)

    if find_cause(error, ConnectionResetError) is not None or err_errno in (errno.ECONNRESET, config.WSAECONNRESET) or "connection reset" in full_text:
        if stage == "tls_handshake":
            return ("[bold red]TLS RST[/bold red]", "TCP RST на ClientHello", bytes_read)
        if stage == "tls_connected":
            return ("[bold red]TLS RST[/bold red]", "TCP RST после handshake", bytes_read)
        return ("[bold red]TCP RST[/bold red]", "TCP соединение сброшено", bytes_read)

    if find_cause(error, ConnectionAbortedError) is not None or err_errno in (getattr(errno, 'ECONNABORTED', 103), config.WSAECONNABORTED) or "connection aborted" in full_text:
        if stage in ("tls_handshake", "tls_connected"):
            return ("[bold red]TLS ABORT[/bold red]", "Соединение прервано (Abort)", bytes_read)
        return ("[bold red]TCP ABORT[/bold red]", "TCP соединение прервано", bytes_read)

    if is_timeout_error(error) or err_errno in (errno.ETIMEDOUT, config.WSAETIMEDOUT) or "timed out" in full_text:
        if stage == "tls_handshake":
            return ("[bold red]TLS DROP[/bold red]", "TLS Handshake timeout", bytes_read)
        if stage == "tcp_connect":
            return ("[bold red]SYN DROP[/bold red]", "TCP SYN timeout", bytes_read)
        return ("[red]TIMEOUT[/red]", f"Timeout ({stage})", bytes_read)

    if err_errno in (errno.ENETUNREACH, config.WSAENETUNREACH) or "network is unreachable" in full_text:
        return ("[red]NET UNREACH[/red]", "Нет маршрута (ICMP unreach)", bytes_read)

    if err_errno in (errno.EHOSTUNREACH, config.WSAEHOSTUNREACH) or "no route to host" in full_text:
        return ("[red]HOST UNREACH[/red]", "Нет маршрута до хоста", bytes_read)

    if "all connection attempts failed" in full_text:
        return ("[bold red]REFUSED[/bold red]", "TCP соединение отклонено", bytes_read)

    return (f"[red]UNKNOWN[/red] [dim]{type(error).__name__}[/dim]",
            clean_detail(str(error)[:40]), bytes_read)


def classify_read_error(error: Exception, bytes_read: int, stage: str = "unknown") -> Tuple[str, str, int]:
    full_text = collect_error_text(error)
    err_errno = get_errno_from_chain(error)

    if find_cause(error, ConnectionResetError) is not None \
            or err_errno in (errno.ECONNRESET, config.WSAECONNRESET) \
            or "connection reset" in full_text:
        if stage == "tls_handshake":
            return ("[bold red]TLS RST[/bold red]", "TCP RST на ClientHello", bytes_read)
        if stage == "tls_connected":
            return ("[bold red]TLS RST[/bold red]", "TCP RST после handshake", bytes_read)
        return ("[bold red]TCP RST[/bold red]", "TCP соединение сброшено", bytes_read)

    if find_cause(error, ConnectionAbortedError) is not None \
            or err_errno in (getattr(errno, 'ECONNABORTED', 103), config.WSAECONNABORTED) \
            or "connection aborted" in full_text:
        if stage in ("tls_handshake", "tls_connected"):
            return ("[bold red]TLS ABORT[/bold red]", "Соединение прервано (Abort)", bytes_read)
        return ("[bold red]TCP ABORT[/bold red]", "TCP соединение прервано", bytes_read)

    if find_cause(error, BrokenPipeError) is not None \
            or err_errno == errno.EPIPE \
            or "broken pipe" in full_text:
        return ("[bold red]RST[/bold red]", "Broken pipe", bytes_read)

    if isinstance(error, httpx.RemoteProtocolError) or "remoteprotocolerror" in full_text:
        if "peer closed" in full_text or "connection closed" in full_text:
            return ("[bold red]ABORT[/bold red]", "Closed early", bytes_read)
        if "incomplete" in full_text:
            return ("[bold red]ABORT[/bold red]", "Incomplete response", bytes_read)
        return (f"[red]UNKNOWN[/red] [dim]{type(error).__name__}[/dim]", "Protocol error", bytes_read)
    if isinstance(error, httpx.ReadError):
        ssl_err = find_cause(error, ssl.SSLError)
        if ssl_err is not None:
            return classify_ssl_error(ssl_err, bytes_read)
        return (f"[red]UNKNOWN[/red] [dim]{type(error).__name__}[/dim]", "Read error", bytes_read)

    # Таймауты чтения/записи: соединение и TLS установлены, но ответа нет —
    # это свойство сервера, а не блокировка
    if isinstance(error, (httpx.ReadTimeout, httpx.WriteTimeout)) \
            or is_timeout_error(error) \
            or err_errno in (errno.ETIMEDOUT, config.WSAETIMEDOUT) \
            or "timed out" in full_text:
        if stage in ("tls_connected", "reading_data"):
            return ("[red]READ TIMEOUT[/red]", "Нет ответа после handshake", bytes_read)
        if stage == "sending_data":
            return ("[red]SEND TIMEOUT[/red]", "Сервер не принимает данные", bytes_read)
        return ("[red]TIMEOUT[/red]", f"Timeout ({stage})", bytes_read)

    return (f"[red]UNKNOWN[/red] [dim]{type(error).__name__}[/dim]", "", bytes_read)

def get_exception_chain_full(exc: Exception) -> str:
    """Возвращает полную детализированную цепочку исключений для отладки."""
    chain = []
    current = exc
    depth = 0
    while current and depth < 10:
        exc_name = current.__class__.__name__
        msg = str(current).strip()

        err_info = ""
        if isinstance(current, OSError) and current.errno:
            err_info = f" (errno={current.errno}, {errno.errorcode.get(current.errno, 'UNKNOWN')})"

        chain.append(f"[{depth}] {exc_name}{err_info}: {msg}")

        current = current.__cause__ or current.__context__
        depth += 1

    return " | ".join(chain)
