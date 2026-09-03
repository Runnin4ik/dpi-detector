"""DoH (DNS over HTTPS) утилиты и вспомогательные функции."""

import re
import ssl
import httpx


def _doh_exc_status(exc: Exception) -> str:
    """
    Классификация исключения DoH-пробы.
    BLOCKED — активное вмешательство: подмена/ошибка сертификата (MITM)
    или сброс соединения при подключении (SNI-блокировка).
    ERROR  — прочие ошибки (HTTP 5xx, кривой ответ, протокол).
    """
    e = exc
    while e is not None:
        if isinstance(e, ssl.SSLError):
            return "BLOCKED"
        e = getattr(e, "__cause__", None) or getattr(e, "__context__", None)
    if isinstance(exc, httpx.ConnectError):
        return "BLOCKED"
    return "ERROR"


def _doh_url_with_port(url: str, port: int) -> str:
    """Вставляет/заменяет порт в https:// URL DoH (нестандартный порт)."""
    m = re.match(r"^(https?://)([^/]+)(/.*)?$", url)
    if not m:
        return url
    scheme, host, path = m.group(1), m.group(2), m.group(3) or ""
    if ":" in host:
        host = host.rsplit(":", 1)[0]
    return f"{scheme}{host}:{port}{path}"
