"""Запросы принадлежности AS / организации через Team Cymru (DoH RFC 8484)."""

from typing import Optional
import asyncio
import os
import re
import json
import tempfile
import ipaddress
import logging
import httpx

from utils import config
from utils.network import pin_host, get_fake_ip_type
from core.dns.wire import _build_dns_query, _parse_txt_response

logger = logging.getLogger(__name__)


def get_asn_cache_file() -> str:
    return getattr(
        config, "ASN_CACHE_FILE",
        os.path.join(tempfile.gettempdir(), "dpi_detector_asn_cache.json"),
    ) or os.path.join(tempfile.gettempdir(), "dpi_detector_asn_cache.json")


def _load_asn_cache(cache_file: Optional[str] = None) -> dict:
    fpath = cache_file or get_asn_cache_file()
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.debug("Failed to load ASN cache: %s", e)
        return {}


def _save_asn_cache(fresh: dict, cache_file: Optional[str] = None) -> None:
    if not fresh:
        return
    fpath = cache_file or get_asn_cache_file()
    cache = _load_asn_cache(fpath)
    cache.update(fresh)
    try:
        cache_dir = os.path.dirname(fpath) or tempfile.gettempdir()
        with tempfile.NamedTemporaryFile("w", dir=cache_dir, delete=False, encoding="utf-8") as tf:
            json.dump(cache, tf)
            temp_name = tf.name
        os.replace(temp_name, fpath)
    except Exception as e:
        logger.debug("Failed to write ASN cache: %s", e)


async def _lookup_asn_name(client: httpx.AsyncClient, ip: str, cymru_doh: Optional[tuple] = None) -> Optional[str]:
    """Имя организации по IP через Team Cymru (DoH RFC 8484, TXT-запрос)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip_obj.version == 6:
        rev = ".".join(reversed(ip_obj.exploded.replace(":", "")))
        q_name = f"{rev}.origin6.asn.cymru.com"
    else:
        rev = ".".join(reversed(ip.split(".")))
        q_name = f"{rev}.origin.asn.cymru.com"

    tq = _build_dns_query(q_name, qtype=16)
    asn = None
    urls = cymru_doh or tuple(getattr(config, "CYMRU_DOH_SERVERS",
                                      ("https://dns.google/dns-query",
                                       "https://cloudflare-dns.com/dns-query",
                                       "https://common.dot.dns.yandex.net/dns-query")))
    for url, ehost in [await pin_host(u) for u in urls]:
        headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
        if ehost:
            headers["Host"] = ehost
        ext = {"sni_hostname": ehost} if ehost else None
        try:
            resp = await client.post(url, content=tq, headers=headers, extensions=ext)
            if resp.status_code != 200:
                continue
            txt = _parse_txt_response(resp.content)
            if txt is None:
                continue
            m = re.match(r"\s*(\d+)", txt.split("|")[0].strip())
            if m:
                asn = m.group(1)
                break
        except Exception as e:
            logger.debug("Cymru origin query error: %s", e)
            continue

    if not asn:
        return None

    for url, ehost in [await pin_host(u) for u in urls]:
        headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
        if ehost:
            headers["Host"] = ehost
        ext = {"sni_hostname": ehost} if ehost else None
        try:
            resp = await client.post(
                url, content=_build_dns_query(f"AS{asn}.asn.cymru.com", qtype=16),
                headers=headers, extensions=ext,
            )
            if resp.status_code != 200:
                continue
            txt = _parse_txt_response(resp.content)
            if txt is None:
                continue
            fields = [p.strip() for p in txt.strip('"').split("|")]
            name = fields[-1] if len(fields) >= 3 else fields[0]
            return re.sub(r"\s+", " ", name).strip() or None
        except Exception as e:
            logger.debug("Cymru AS name query error: %s", e)
            continue
    return None


async def resolve_asn_names(egress_ips: list[str], proxy_url: Optional[str] = None) -> dict[str, str]:
    """Резолвит имена ASN для списка egress-IP с кэшированием."""
    uniq = sorted({e for e in egress_ips if e and e != "0.0.0.0" and get_fake_ip_type(e) != "fakeip"})
    if not uniq:
        return {}
    cache = _load_asn_cache()
    out = {i: cache[i] for i in uniq if isinstance(cache.get(i), str)}
    missing = [i for i in uniq if i not in out]
    if not missing:
        return out
    headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}
    sem = asyncio.Semaphore(getattr(config, "DNS_ASN_CONCURRENCY", 8))
    fresh: dict[str, str] = {}
    async with httpx.AsyncClient(
        timeout=4, headers=headers, http2=True,
        proxy=proxy_url, trust_env=False,
    ) as cli:
        async def one(uip: str):
            async with sem:
                nm = await _lookup_asn_name(cli, uip)
                return uip, nm
        for uip, nm in await asyncio.gather(*[one(i) for i in missing]):
            if nm:
                out[uip] = nm
                fresh[uip] = nm
    if fresh:
        _save_asn_cache(fresh)
    return out
