import asyncio
import socket
import ipaddress
from typing import Optional

async def get_resolved_ip(domain: str, family: int = socket.AF_INET) -> Optional[str]:
    """
    Резолвит домен в IP-адрес. До 2 попыток при сбое.
    family: socket.AF_INET для IPv4, socket.AF_INET6 для IPv6.
    Использует системный DNS — если провайдер подменяет системный резолвер,
    но не прямой UDP/53, stub_ips из DNS-теста не совпадут с resolved_ip.
    """
    loop = asyncio.get_running_loop()
    for attempt in range(2):
        try:
            addrs = await loop.getaddrinfo(
                domain, 443, family=family, type=socket.SOCK_STREAM
            )
            if addrs:
                return addrs[0][4][0]
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.2)
                continue
            break
    return None


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
        if not isinstance(ip, ipaddress.IPv4Address):
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