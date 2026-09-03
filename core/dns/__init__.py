"""DNS подсистема: wire-format, протоколы (UDP/DoH/DoT/SOCKS5), stub-IP и ASN."""

from core.dns.wire import (
    _build_dns_query,
    _skip_dns_name,
    _parse_dns_response,
    _parse_txt_response,
)
from core.dns.socks import (
    _parse_socks_proxy,
    _unwrap_socks_udp,
    _Socks5UdpRelay,
)
from core.dns.udp import (
    _SingleQueryProto,
    probe_resolver_ip,
)
from core.dns.doh import (
    _doh_exc_status,
    _doh_url_with_port,
)
from core.dns.dot import (
    _split_dot_endpoint,
    create_dot_ssl_context,
)
from core.dns.asn import (
    _lookup_asn_name,
    _load_asn_cache,
    _save_asn_cache,
    resolve_asn_names,
)
from core.dns.stubs import (
    _known_resolver,
    _dns_name_sort_key,
    _resolve_udp_native,
    _probe_udp_all,
    collect_stub_ips_silently,
)
from core.dns.render import render_dns_availability_results

__all__ = [
    "_SingleQueryProto",
    "_Socks5UdpRelay",
    "_build_dns_query",
    "_dns_name_sort_key",
    "_doh_exc_status",
    "_doh_url_with_port",
    "_known_resolver",
    "_load_asn_cache",
    "_lookup_asn_name",
    "_parse_dns_response",
    "_parse_socks_proxy",
    "_parse_txt_response",
    "_probe_udp_all",
    "_resolve_udp_native",
    "_save_asn_cache",
    "_skip_dns_name",
    "_split_dot_endpoint",
    "create_dot_ssl_context",
    "_unwrap_socks_udp",
    "collect_stub_ips_silently",
    "probe_resolver_ip",
    "render_dns_availability_results",
    "resolve_asn_names",
]
