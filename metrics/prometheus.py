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
from typing import Dict, Optional

# ─── Gauge storage ────────────────────────────────────────────────────────────

_metrics: Dict[str, object] = {}
_lock = threading.Lock()
_last_run_ts: float = 0.0


def record_dns(total: int, intercepted: int, ok: int) -> None:
    """Update DNS check metrics."""
    with _lock:
        _metrics["dpi_dns_total"] = total
        _metrics["dpi_dns_intercepted"] = intercepted
        _metrics["dpi_dns_ok"] = ok


def record_domains(total: int, ok: int, blocked: int, timeout: int, dns_fail: int) -> None:
    """Update domain reachability metrics."""
    with _lock:
        _metrics["dpi_domains_total"] = total
        _metrics["dpi_domains_ok"] = ok
        _metrics["dpi_domains_blocked"] = blocked
        _metrics["dpi_domains_timeout"] = timeout
        _metrics["dpi_domains_dns_fail"] = dns_fail


def record_tcp(total: int, ok: int, blocked: int, mixed: int) -> None:
    """Update TCP 16-20KB DPI metrics."""
    with _lock:
        _metrics["dpi_tcp_total"] = total
        _metrics["dpi_tcp_ok"] = ok
        _metrics["dpi_tcp_blocked"] = blocked
        _metrics["dpi_tcp_mixed"] = mixed


def record_run_timestamp() -> None:
    """Update timestamp of last completed check run."""
    global _last_run_ts
    with _lock:
        _last_run_ts = time.time()


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

    for name, (mtype, help_text) in meta.items():
        value = snapshot.get(name)
        if value is None:
            continue
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    # Last run timestamp
    lines.append("# HELP dpi_last_run_timestamp_seconds Unix timestamp of last completed test run")
    lines.append("# TYPE dpi_last_run_timestamp_seconds gauge")
    lines.append(f"dpi_last_run_timestamp_seconds {ts:.3f}")

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
