"""Детекция запущенных локально инструментов обхода DPI и VPN."""

from typing import List
import os
import sys
import subprocess

from utils import config

_DEFAULT_BYPASS_TOOLS = (
    ("zapret",       ("nfqws", "tpws", "zapret", "dvtws", "dbproxy", "winws")),
    ("GoodbyeDPI",   ("goodbyedpi", "goodbye-dpi", "windivert")),
    ("ByeDPI",       ("byedpi",)),
    ("SpoofDPI",     ("spoofdpi",)),
    ("DPI-Blocker",  ("dpi-blocker", "dpiblocker")),
    ("Green Tunnel", ("greentunnel", "green-tunnel")),
    ("PowerTunnel",  ("powertunnel",)),
    ("Hysteria2",    ("hysteria",)),
    ("TROJAN",       ("trojan", "trojan-go")),
    ("NaiveProxy",   ("naive",)),
    ("Wstunnel",     ("wstunnel",)),
    ("UDP2RAW",      ("udp2raw",)),
    ("dnscrypt-proxy", ("dnscrypt-proxy",)),
    ("xray",         ("xray",)),
    # FlClashX: сам GUI и mihomo-ядро; HelperService — фоновый, DPI не обходит
    ("FlClashX",     ("flclashx", "flclashcore")),
    ("AmneziaWG",    ("amneziawg",)),
    ("Clash",        ("mihomo", "clash-meta", "clash-verge", "clash_verge",
                      "verge-mihomo")),
    ("sing-box",     ("sing-box",)),
    ("Hiddify",      ("hiddify",)),   # ядро sing-box встроено в Hiddify.exe
    ("Tailscale",    ("tailscale",)),
    ("ZeroTier",     ("zerotier",)),
    ("Mullvad",      ("mullvad",)),
    ("WARP",         ("warp-svc", "cloudflarewarp")),
    ("NordVPN",      ("nordvpn",)),
)


def _get_bypass_tools() -> tuple:
    configured = getattr(config, "BYPASS_TOOLS", None)
    source = configured if configured else _DEFAULT_BYPASS_TOOLS
    return tuple(
        (str(name), frozenset(str(p).lower() for p in procs))
        for name, procs in source
    )


_BYPASS_TOOLS = _get_bypass_tools()


def detect_bypass_tools() -> List[str]:
    """Запущенные локально обходы DPI (по именам процессов). Пусто — ничего нет."""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, errors="replace", timeout=10, check=False,
            ).stdout
            names = [l.split('","')[0].strip('"').lower() for l in out.splitlines() if l.strip()]
        else:
            out = subprocess.run(
                ["ps", "-e", "-o", "comm="],
                capture_output=True, text=True, errors="replace", timeout=10, check=False,
            ).stdout
            names = [os.path.basename(l.strip()).lower() for l in out.splitlines() if l.strip()]
    except Exception:
        return []
    clean_names = {
        n[:-4] if n.endswith(".exe") else n
        for n in names
    }
    found: List[str] = []
    for tool, patterns in _get_bypass_tools():
        if patterns & clean_names:
            found.append(tool)
    return found
