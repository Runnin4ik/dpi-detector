import ssl


def create_dot_ssl_context() -> ssl.SSLContext:
    """Создаёт SSLContext для DoT (RFC 7858) с поддержкой certifi и системных сертификатов."""
    try:
        import certifi
        cafile = certifi.where()
    except Exception:
        cafile = None

    if cafile:
        try:
            ctx = ssl.create_default_context(cafile=cafile)
        except Exception:
            ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()

    try:
        ctx.load_default_certs()
    except Exception:
        pass

    return ctx


"""DoT (DNS over TLS, RFC 7858) утилиты и вспомогательные функции."""


def _split_dot_endpoint(addr: str) -> tuple:
    """'host[:port]' → (host, port); порт по умолчанию 853. Поддерживает IPv6."""
    s = addr.strip()
    if s.startswith("["):
        if "]:" in s:
            host, _, port = s.rpartition(":")
            return host.strip("[]"), int(port)
        return s.strip("[]"), 853
    if s.count(":") >= 2:
        return s, 853
    if ":" in s:
        host, _, port = s.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return s, 853
    return s, 853
