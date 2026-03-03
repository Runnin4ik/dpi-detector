"""Prometheus metrics server for dpi-detector Docker mode.

Exposes /metrics endpoint on METRICS_PORT (default: 9090) with Basic Auth.
Credentials are configured via env vars METRICS_USER and METRICS_PASSWORD.
"""
from __future__ import annotations

import base64
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple

# ─── Gauge storage ────────────────────────────────────────────────────────────

_metrics: Dict[str, object] = {}
_lock = threading.Lock()
_last_run_ts: float = 0.0

# Per-domain: {domain: {"http": str, "tls12": str, "tls13": str, "https": str}}
_domain_status: Dict[str, Dict[str, str]] = {}

# Per-TCP-target: {target_id: {"provider": str, "asn": str, "status": str}}
# status: "ok" | "blocked" | "mixed" | "unknown"
_tcp_target_status: Dict[str, Dict[str, str]] = {}


def record_dns(total: int, intercepted: int, ok: int) -> None:
    """Update DNS check metrics."""
    with _lock:
        _metrics["dpi_dns_total"] = total
        _metrics["dpi_dns_intercepted"] = intercepted
        _metrics["dpi_dns_ok"] = ok


def record_domains(total: int, ok: int, blocked: int, timeout: int, dns_fail: int) -> None:
    """Update domain reachability aggregate metrics."""
    with _lock:
        _metrics["dpi_domains_total"] = total
        _metrics["dpi_domains_ok"] = ok
        _metrics["dpi_domains_blocked"] = blocked
        _metrics["dpi_domains_timeout"] = timeout
        _metrics["dpi_domains_dns_fail"] = dns_fail


def record_domain_statuses(statuses: List[Tuple[str, Dict[str, str]]]) -> None:
    """Update per-domain availability metrics.

    Args:
        statuses: list of (domain, status_dict)
    """
    with _lock:
        _domain_status.clear()
        for domain, status_dict in statuses:
            _domain_status[domain] = status_dict


def record_tcp(total: int, ok: int, blocked: int, mixed: int) -> None:
    """Update TCP 16-20KB DPI aggregate metrics."""
    with _lock:
        _metrics["dpi_tcp_total"] = total
        _metrics["dpi_tcp_ok"] = ok
        _metrics["dpi_tcp_blocked"] = blocked
        _metrics["dpi_tcp_mixed"] = mixed


def record_tcp_target_statuses(targets: List[Dict[str, str]]) -> None:
    """Update per-TCP-target availability metrics.

    Args:
        targets: list of dicts with keys: "id", "provider", "asn", "status"
                 status is one of: "ok", "blocked", "mixed", "unknown"
    """
    with _lock:
        _tcp_target_status.clear()
        for t in targets:
            _tcp_target_status[t["id"]] = {
                "provider": t.get("provider", ""),
                "asn": t.get("asn", ""),
                "status": t.get("status", "unknown"),
            }


def record_run_timestamp() -> None:
    """Update timestamp of last completed check run."""
    global _last_run_ts
    with _lock:
        _last_run_ts = time.time()


def _escape_label(value: str) -> str:
    """Escape label value for Prometheus text format."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_metrics() -> str:
    """Render metrics in Prometheus text format."""
    lines: list[str] = []

    meta = {
        "dpi_dns_total":          ("gauge", "Total DNS domains checked"),
        "dpi_dns_intercepted":    ("gauge", "DNS domains intercepted/replaced by ISP"),
        "dpi_dns_ok":             ("gauge", "DNS domains resolving correctly"),
        "dpi_domains_total":      ("gauge", "Total domains tested for DPI blocking"),
        "dpi_domains_ok":         ("gauge", "Domains accessible (TLS OK)"),
        "dpi_domains_blocked":    ("gauge", "Domains blocked by DPI"),
        "dpi_domains_timeout":    ("gauge", "Domains that timed out"),
        "dpi_domains_dns_fail":   ("gauge", "Domains with DNS resolution failure"),
        "dpi_tcp_total":          ("gauge", "Total TCP 16-20KB probes"),
        "dpi_tcp_ok":             ("gauge", "TCP probes passed (DPI not detected)"),
        "dpi_tcp_blocked":        ("gauge", "TCP probes blocked (DPI detected)"),
        "dpi_tcp_mixed":          ("gauge", "TCP probes with mixed results"),
    }

    with _lock:
        snapshot = dict(_metrics)
        ts = _last_run_ts
        domain_snap = dict(_domain_status)
        tcp_snap = dict(_tcp_target_status)

    # ── Aggregate metrics ──────────────────────────────────────────────────────
    for name, (mtype, help_text) in meta.items():
        value = snapshot.get(name)
        if value is None:
            continue
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    # ── Last run timestamp ─────────────────────────────────────────────────────
    lines.append("# HELP dpi_last_run_timestamp_seconds Unix timestamp of last completed test run")
    lines.append("# TYPE dpi_last_run_timestamp_seconds gauge")
    lines.append(f"dpi_last_run_timestamp_seconds {ts:.3f}")

    # ── Per-domain availability ────────────────────────────────────────────────
    if domain_snap:
        lines.append("# HELP dpi_domain_available Per-domain availability status (HTTPS overall, 1=current state)")
        lines.append("# TYPE dpi_domain_available gauge")
        for domain, statuses in sorted(domain_snap.items()):
            if isinstance(statuses, dict):
                s = statuses.get("https", "unknown")
            else:
                s = statuses
            d_esc = _escape_label(domain)
            s_esc = _escape_label(s)
            lines.append(f'dpi_domain_available{{domain="{d_esc}",status="{s_esc}"}} 1')

        lines.append("# HELP dpi_domain_ok Per-domain reachability: 1=ok, 0=not ok")
        lines.append("# TYPE dpi_domain_ok gauge")
        for domain, statuses in sorted(domain_snap.items()):
            d_esc = _escape_label(domain)
            if isinstance(statuses, dict):
                val = 1 if statuses.get("https") == "ok" else 0
            else:
                val = 1 if statuses == "ok" else 0
            lines.append(f'dpi_domain_ok{{domain="{d_esc}"}} {val}')

        lines.append("# HELP dpi_domain_tls_status Per-domain TLS version status")
        lines.append("# TYPE dpi_domain_tls_status gauge")
        for domain, statuses in sorted(domain_snap.items()):
            if not isinstance(statuses, dict):
                continue
            d_esc = _escape_label(domain)
            t12_esc = _escape_label(statuses.get("tls12", "unknown"))
            t13_esc = _escape_label(statuses.get("tls13", "unknown"))
            lines.append(f'dpi_domain_tls_status{{domain="{d_esc}",tls_version="1.2",status="{t12_esc}"}} 1')
            lines.append(f'dpi_domain_tls_status{{domain="{d_esc}",tls_version="1.3",status="{t13_esc}"}} 1')

    # ── Per-TCP-target status ──────────────────────────────────────────────────
    if tcp_snap:
        lines.append("# HELP dpi_tcp_target_status Per-TCP-target DPI status (1=current state)")
        lines.append("# TYPE dpi_tcp_target_status gauge")
        for tid, info in sorted(tcp_snap.items()):
            t_esc = _escape_label(tid)
            p_esc = _escape_label(info["provider"])
            a_esc = _escape_label(info["asn"])
            s_esc = _escape_label(info["status"])
            lines.append(
                f'dpi_tcp_target_status{{id="{t_esc}",provider="{p_esc}",asn="{a_esc}",status="{s_esc}"}} 1'
            )

        lines.append("# HELP dpi_tcp_target_ok Per-TCP-target: 1=ok (DPI not detected), 0=blocked/mixed")
        lines.append("# TYPE dpi_tcp_target_ok gauge")
        for tid, info in sorted(tcp_snap.items()):
            t_esc = _escape_label(tid)
            p_esc = _escape_label(info["provider"])
            a_esc = _escape_label(info["asn"])
            value = 1 if info["status"] == "ok" else 0
            lines.append(
                f'dpi_tcp_target_ok{{id="{t_esc}",provider="{p_esc}",asn="{a_esc}"}} {value}'
            )

    return "\n".join(lines) + "\n"


# ─── HTTP handler ──────────────────────────────────────────────────────────────

class _MetricsHandler(BaseHTTPRequestHandler):
    _credentials: Optional[str] = None  # base64-encoded "user:password"

    def log_message(self, fmt: str, *args) -> None:  # silence default access log
        pass

    def _check_auth(self) -> bool:
        if not self._credentials:
            return True
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            return False
        provided = auth_header[len("Basic "):].strip()
        return provided == self._credentials

    def _send_unauthorized(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="DPI Detector Metrics"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Unauthorized")

    def do_GET(self) -> None:
        if not self._check_auth():
            self._send_unauthorized()
            return

        if self.path in ("/metrics", "/metrics/"):
            body = _render_metrics().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/", "/health"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()


def start_metrics_server() -> None:
    """Start Prometheus metrics HTTP server in a daemon thread.

    Env vars:
        METRICS_PORT     - TCP port to listen on (default: 9090)
        METRICS_USER     - Basic Auth username (default: empty = no auth)
        METRICS_PASSWORD - Basic Auth password (default: empty = no auth)
    """
    port = int(os.environ.get("METRICS_PORT", "9090"))
    user = os.environ.get("METRICS_USER", "")
    password = os.environ.get("METRICS_PASSWORD", "")

    if user and password:
        raw = f"{user}:{password}"
        _MetricsHandler._credentials = base64.b64encode(raw.encode()).decode()
    else:
        _MetricsHandler._credentials = None

    server = HTTPServer(("", port), _MetricsHandler)

    thread = threading.Thread(target=server.serve_forever, daemon=True, name="metrics-server")
    thread.start()
    print(f"[metrics] Prometheus endpoint: http://0.0.0.0:{port}/metrics", flush=True)
    if _MetricsHandler._credentials:
        print(f"[metrics] Basic Auth enabled (user={user})", flush=True)
    else:
        print("[metrics] Basic Auth disabled (set METRICS_USER + METRICS_PASSWORD to enable)", flush=True)
