import asyncio
import socket
import ipaddress
import logging
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)


def mask_proxy_url(url: Optional[str]) -> str:
    """Маскирует пароль в URL прокси: socks5://user:pass@host:port -> socks5://user:***@host:port."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        if parts.password:
            user = parts.username or ""
            host = parts.hostname or ""
            port = f":{parts.port}" if parts.port else ""
            masked_netloc = f"{user}:***@{host}{port}"
            return urlunsplit((parts.scheme, masked_netloc, parts.path, parts.query, parts.fragment))
        return url
    except Exception:
        return url

def create_insecure_dpi_ssl_context(tls_version: Optional[str] = None):
    """Создаёт SSLContext с CERT_NONE и check_hostname=False ИСКЛЮЧИТЕЛЬНО для DPI-зондирования
    (детекция MITM/подмены сертификатов ТСПУ/DPI и анализ L4-блокировок).
    Категорически запрещено использовать для передачи учетных данных, API или обновлений.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls_version == "TLSv1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx

def _ip_family() -> int:
    """AF_INET6 если config.IP_VERSION == "ipv6", иначе AF_INET."""
    from utils import config
    return socket.AF_INET6 if getattr(config, "IP_VERSION", "ipv4") == "ipv6" else socket.AF_INET


def ipv6_supported() -> bool:
    """True, если в системе настроен глобально адресуемый IPv6 (2000::/3).

    Раньше проверялся только getaddrinfo(None, None, AF_INET6, AI_PASSIVE) —
    он возвращает bind-wildcard ``::`` (is_unspecified), а не адреса интерфейсов,
    поэтому глобальный адрес не находился даже при настроенном IPv6.
    Теперь адреса собираются из имени хоста (все IPv6 интерфейса) и из
    source-адреса, который ОС выбрала бы для маршрута в глобальный IPv6.
    """
    if not socket.has_ipv6:
        return False

    candidates = []
    # 1) Адреса, назначенные хосту: hostname-резолв перечисляет все IPv6 адреса,
    #    включая глобальные 2000::/3 (AI_PASSIVE этого не делает).
    for host, flags in ((socket.gethostname(), 0),
                        (None, socket.AI_PASSIVE | socket.AI_ADDRCONFIG)):
        try:
            infos = socket.getaddrinfo(
                host, None, family=socket.AF_INET6, type=socket.SOCK_STREAM,
                flags=flags,
            )
        except OSError:
            continue
        for info in infos:
            candidates.append(info[4][0])

    # 2) Source-адрес, выбранный ОС для маршрута в глобальный IPv6. UDP connect()
    #    пакет не отправляет, только просит ОС подобрать локальный адрес.
    for addr in ("2001:4860:4860::8888", "2606:4700:4700::1111", "2620:fe::fe"):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s.connect((addr, 53))
                candidates.append(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            continue

    for raw in candidates:
        try:
            ip = ipaddress.ip_address(raw.split("%")[0])
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.is_global:
            return True
    return False


async def get_resolved_ip(domain: str, family: int = None) -> Optional[str]:
    """
    Резолвит домен в IP-адрес. До 2 попыток при сбое.
    family: socket.AF_INET для IPv4, socket.AF_INET6 для IPv6.
    family=None → берётся из config.IP_VERSION ("ipv4"/"ipv6").
    Использует системный DNS — если провайдер подменяет системный резолвер,
    но не прямой UDP/53, stub_ips из DNS-теста не совпадут с resolved_ip.
    """
    if family is None:
        family = _ip_family()
    loop = asyncio.get_running_loop()
    for attempt in range(2):
        try:
            addrs = await loop.getaddrinfo(
                domain, 443, family=family, type=socket.SOCK_STREAM
            )
            if addrs:
                return addrs[0][4][0]
        except Exception as e:
            logger.debug("getaddrinfo failed for %s: %s", domain, e)
            if attempt == 0:
                await asyncio.sleep(0.2)
                continue
            break
    return None


def is_ip_literal(host: str) -> bool:
    """True если host — IPv4- или IPv6-литерал."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def format_ip_for_url(ip: str) -> str:
    """IPv6-литерал для URL: оборачивает в квадратные скобки (иначе не парсится)."""
    if ":" in ip and not ip.startswith("["):
        return f"[{ip}]"
    return ip


def get_fake_ip_type(ip_str: str) -> str:
    """
    Возвращает:
    'fakeip' - (198.18.0.0/15)
    'isp'    - для сетей провайдера (CGNAT)
    'local'  - для локальных сетей (LAN, localhost, нули)
    None     - если это обычный публичный IP
    """
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
                return "local"
            return None
        # 198.18.0.0/15 — Fake-IP
        if ip in ipaddress.ip_network('198.18.0.0/15'):
            return "fakeip"

        # 100.64.0.0/10 — Carrier-Grade NAT (заглушки провайдер)
        if ip in ipaddress.ip_network('100.64.0.0/10'):
            return "isp"

        # Локальные сети (10.x, 192.168.x, 172.16.x, Loopback, нули)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            return "local"

        return None
    except ValueError:
        return None

def is_local_or_relay_ip(ip_str: str) -> bool:
    """True, если IP — локальный/приватный, петлевой, fake-ip или CGNAT-шлюз/релей."""
    if not ip_str:
        return False
    fake_type = get_fake_ip_type(ip_str)
    if fake_type in ("fakeip", "local", "isp"):
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved
    except ValueError:
        return False


from time import monotonic as _monotonic

from utils import config

_pin_cache: dict = {}
_PIN_CACHE_MAX = 256     # дефолтный максимум записей
_PIN_CACHE_TTL = 3600.0  # дефолтный TTL в секундах


def clear_pin_cache() -> None:
    """Очищает кэш пининга хостов (при смене PROXY_URL или IP_VERSION)."""
    _pin_cache.clear()


async def pin_host(url: str):
    """
    Привязка HTTP-тестов к IP выбранного семейства (config.IP_VERSION):
    хост в URL заменяется на его A-/AAAA-запись, чтобы соединение не ушло
    в другое семейство через системный getaddrinfo.
    Возвращает (url, host): host нужно передать в запросе заголовком Host
    и расширением sni_hostname — иначе сервер и проверка сертификата
    увидят IP вместо имени. Если задан PROXY_URL (резолв выполняет прокси),
    хост уже IP-литерал или записи нет — возвращается (url, None),
    соединение пойдёт как раньше. Результат кэшируется на время сессии.
    """
    now = _monotonic()
    cached = _pin_cache.get(url)
    ttl = getattr(config, "PIN_CACHE_TTL", _PIN_CACHE_TTL)
    max_entries = getattr(config, "PIN_CACHE_MAX", _PIN_CACHE_MAX)
    if cached is not None and now - cached[0] < ttl:
        return cached[1]

    result = (url, None)
    should_cache = True
    try:
        from ipaddress import ip_address
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
        host = parts.hostname
        if host and not getattr(config, "PROXY_URL", None):
            try:
                ip_address(host)  # уже литерал — резолвить нечего
            except ValueError:
                ip = await get_resolved_ip(host)
                if ip:
                    if ":" in ip and not ip.startswith("["):
                        ip = f"[{ip}]"
                    netloc = ip if parts.port is None else f"{ip}:{parts.port}"
                    new_url = urlunsplit(
                        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
                    )
                    result = (new_url, host)
                else:
                    should_cache = False  # не кэшируем временный сбой DNS
    except Exception as e:
        logger.debug("pin_host failed for %s: %s", url, e)
        should_cache = False

    if should_cache:
        if len(_pin_cache) >= max_entries and _pin_cache:
            _pin_cache.pop(next(iter(_pin_cache)))
        _pin_cache[url] = (now, result)
    return result
