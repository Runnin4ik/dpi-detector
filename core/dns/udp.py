"""UDP DNS-зондирование и резолв вышестоящих серверов."""

from typing import Optional
import asyncio
import time
import logging

from core.dns.wire import _build_dns_query, _parse_dns_response

logger = logging.getLogger(__name__)


class _SingleQueryProto(asyncio.DatagramProtocol):
    """Одиночный UDP DNS-запрос: отдаёт (data, t_recv) в future."""

    def __init__(self, fut):
        self.fut = fut

    def datagram_received(self, data, _addr):
        t_recv = time.perf_counter()
        if not self.fut.done():
            self.fut.set_result((data, t_recv))

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        err = exc or ConnectionError("Socket closed")
        if not self.fut.done():
            self.fut.set_exception(err)


async def probe_resolver_ip(server_ip: str, timeout: float = 2.0) -> Optional[str]:
    """IP вышестоящего резолвера через server_ip:53.

    A whoami.akamai.net: авторитетный сервер возвращает адрес рекурсивного
    резолвера, от которого пришёл запрос. Если роутер работает DNS-релеем
    (dnsmasq/unbound), это IP его upstream. None — не удалось.
    """
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    transport = None
    try:
        q = _build_dns_query("whoami.akamai.net")
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _SingleQueryProto(fut), remote_addr=(server_ip, 53)
        )
        transport.sendto(q)
        data, _t = await asyncio.wait_for(fut, timeout=timeout)
        parsed = _parse_dns_response(data, q[:2])
        if isinstance(parsed, list) and parsed:
            return parsed[0]
    except Exception as e:
        logger.debug("probe_resolver_ip error for %s: %s", server_ip, e, exc_info=True)
    finally:
        if transport:
            transport.close()
    return None
