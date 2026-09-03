"""Обнаружение заглушек провайдера (stub IP) и классификация резолверов."""

from typing import Union, List
import asyncio
import logging

from utils import config
from core.dns.wire import _build_dns_query, _parse_dns_response

logger = logging.getLogger(__name__)

_KNOWN_RESOLVER_NAME_TOKENS = (
    "google", "cloudflare", "quad9", "adguard",
    "opendns", "cisco", "cleanbrowsing", "nextdns",
    "controld", "mullvad", "dns0", "ahadns",
    "comss", "yandex", "geohide", "нсди", "t2",
)

_DNS_ORDER_POPULAR = ("google", "cloudflare", "quad9", "adguard")
_DNS_ORDER_RU = ("xbox", "comss", "yandex", "geohide", "msk", "нсди")


def _known_resolver(name: str) -> bool:
    """Выходной резолвер — известный публичный DNS по имени сервера из конфига."""
    if not name:
        return False
    tokens = getattr(config, "DNS_KNOWN_RESOLVER_NAMES", None) or _KNOWN_RESOLVER_NAME_TOKENS
    low = name.lower()
    return any(tok in low for tok in tokens)


def _dns_name_sort_key(name: str) -> tuple:
    """Ключ сортировки имени провайдера: (тир, позиция в тире, имя)."""
    low = name.lower()
    for i, prefix in enumerate(_DNS_ORDER_POPULAR):
        if low.startswith(prefix):
            return (0, i, low)
    if any(low.startswith(p) for p in _DNS_ORDER_RU):
        i = next(i for i, p in enumerate(_DNS_ORDER_RU) if low.startswith(p))
        return (2, i, low)
    return (1, 0, low)


async def _resolve_udp_native(nameserver: str, domain: str, timeout: float) -> Union[List[str], str]:
    """UDP DNS-запрос напрямую через asyncio DatagramProtocol."""
    query = _build_dns_query(domain)
    tx_id = query[:2]

    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            if not future.done():
                future.set_result(data)
        def error_received(self, exc):
            if not future.done():
                future.set_exception(exc)
        def connection_lost(self, exc):
            if not future.done():
                future.set_exception(exc or ConnectionError("UDP closed"))

    transport, _ = await loop.create_datagram_endpoint(
        _Proto, remote_addr=(nameserver, 53)
    )
    try:
        transport.sendto(query)
        resp_data = await asyncio.wait_for(future, timeout=timeout)
        return _parse_dns_response(resp_data, tx_id)
    finally:
        transport.close()


async def _probe_udp_all(nameserver: str, domains: list) -> dict:
    async def _query(domain):
        try:
            res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
            if isinstance(res, list):
                return domain, "OK", res
            if res == "NXDOMAIN":
                return domain, "NXDOMAIN", None
            return domain, "ERROR", None
        except (TimeoutError, asyncio.TimeoutError):
            return domain, "TIMEOUT", None
        except Exception as e:
            logger.debug("DNS UDP query failed for %s: %s", domain, e, exc_info=True)
            return domain, "ERROR", None

    completed = await asyncio.gather(*[_query(d) for d in domains])

    ok = timeout_cnt = error = 0
    results = {}
    for domain, status, res in completed:
        if status == "OK":
            results[domain] = res
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            error += 1

    return {"ok": ok, "timeout": timeout_cnt, "error": error, "results": results}


async def collect_stub_ips_silently() -> set:
    """Тихо собирает IP заглушек провайдера (если DNS-тест не запущен)."""
    probe = None
    for udp_ip, _ in config.DNS_UDP_SERVERS:
        probe = await _probe_udp_all(udp_ip, config.DNS_CHECK_DOMAINS)
        if probe["ok"] > 0:
            break

    if not probe or not probe.get("results"):
        return set()

    ip_count: dict = {}
    for res in probe["results"].values():
        if isinstance(res, list):
            for ip in res:
                ip_count[ip] = ip_count.get(ip, 0) + 1
    threshold = getattr(config, "DNS_STUB_THRESHOLD", 2)
    return {ip for ip, count in ip_count.items() if count >= threshold}
