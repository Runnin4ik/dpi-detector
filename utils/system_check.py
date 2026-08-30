"""Локальная диагностика: системный DNS-резолвер и запущенные обходы DPI."""

import os
import re
import subprocess
import sys
from typing import Dict, List
import glob

from utils import config

_TCPIP_BASE  = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_TCPIP6_BASE = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
_NET_CLASS   = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"

def _live_adapter_guids() -> set:
    """GUID'ы реально существующих адаптеров (реестр Control\\Network), нижний регистр."""
    guids = set()
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NET_CLASS) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                guids.add(winreg.EnumKey(key, i).lower())
    except OSError:
        pass
    return guids


def _adapter_names() -> Dict[str, str]:
    """GUID (нижний регистр) -> имя адаптера из Connection\\Name."""
    names = {}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _NET_CLASS) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                guid = winreg.EnumKey(key, i)
                try:
                    with winreg.OpenKey(key, guid + r"\Connection") as ck:
                        names[guid.lower()] = winreg.QueryValueEx(ck, "Name")[0]
                except OSError:
                    pass
    except OSError:
        pass
    return names


def _windows_build() -> int:
    """Реальный номер сборки Windows через RtlGetVersion (без манифест-маскировки)."""
    try:
        import ctypes
        from ctypes import wintypes

        class OSVERSIONINFOEXW(ctypes.Structure):
            _fields_ = [
                ("dwOSVersionInfoSize", wintypes.DWORD),
                ("dwMajorVersion", wintypes.DWORD),
                ("dwMinorVersion", wintypes.DWORD),
                ("dwBuildNumber", wintypes.DWORD),
                ("dwPlatformId", wintypes.DWORD),
                ("szCSDVersion", wintypes.WCHAR * 128),
                ("wServicePackMajor", wintypes.WORD),
                ("wServicePackMinor", wintypes.WORD),
                ("wSuiteMask", wintypes.WORD),
                ("wProductType", wintypes.BYTE),
                ("wReserved", wintypes.BYTE),
            ]

        info = OSVERSIONINFOEXW()
        info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
        if ctypes.windll.ntdll.RtlGetVersion(ctypes.byref(info)) == 0:
            return int(info.dwBuildNumber)
    except Exception:
        pass
    return int(sys.getwindowsversion().build)


def _windows_doh() -> Dict[str, str]:
    """DoH-конфиг Windows: {сервер: шаблон URL} для серверов с включённым DoH.
    Источник — Dnscache\\InterfaceSpecificParameters\\{GUID}\\DohInterfaceSettings\\
    Doh\\<IPv4> / Doh6\\<IPv6> (DohFlags: бит 0 = автошаблон, бит 1 = кастомный
    шаблон; DohTemplate — URL, который Windows подставляет сама для известных
    резолверов). DoH включён, если DohFlags & 0x0003.
    Ограничения ОС: системного DoH нет на Windows 7/8/10 (сборка < 20348);
    GPO DoHPolicy=1 (Prohibit) принудительно отключает DoH."""
    if _windows_build() < 20348:   # Win7/8/10: системного DoH не существует
        return {}
    doh = {}
    try:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient") as k:
                if winreg.QueryValueEx(k, "DoHPolicy")[0] == 1:   # Prohibit
                    return {}
        except OSError:
            pass
        base = r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                guid = winreg.EnumKey(key, i)
                for folder in ("Doh", "Doh6"):
                    p = base + "\\" + guid + "\\DohInterfaceSettings\\" + folder
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as dk:
                            for j in range(winreg.QueryInfoKey(dk)[0]):
                                ip = winreg.EnumKey(dk, j)
                                try:
                                    with winreg.OpenKey(dk, ip) as ik:
                                        flags = int(winreg.QueryValueEx(ik, "DohFlags")[0])
                                        if flags & 0x0003:
                                            try:
                                                tmpl = winreg.QueryValueEx(ik, "DohTemplate")[0]
                                            except OSError:
                                                tmpl = ""
                                            doh[ip] = tmpl or "doh"
                                except OSError:
                                    continue
                    except OSError:
                        continue
    except OSError:
        pass
    return doh


def _read_dns_entries(guid: str) -> List[tuple]:
    """DNS конкретного интерфейса: [(сервер, 'static'|'dhcp')]."""
    entries: List[tuple] = []
    try:
        import winreg
        for base in (_TCPIP_BASE, _TCPIP6_BASE):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + "\\" + guid) as k:
                    for val, src in (("NameServer", "static"), ("DhcpNameServer", "dhcp"),
                                     ("Dhcpv6DNSServers", "dhcp"), ("ProfileNameServer", "dhcp")):
                        try:
                            raw = winreg.QueryValueEx(k, val)[0]
                        except OSError:
                            continue
                        cand: List[str] = []
                        if isinstance(raw, (bytes, bytearray)):
                            import ipaddress
                            for i in range(0, len(raw) - len(raw) % 16, 16):
                                chunk = bytes(raw[i:i + 16])
                                try:
                                    cand.append(str(ipaddress.IPv6Address(chunk)))
                                except Exception:
                                    pass
                        elif isinstance(raw, (list, tuple)):
                            for item in raw:
                                for s in re.split(r"[,\s]+", str(item)):
                                    if s.strip():
                                        cand.append(s.strip())
                        elif isinstance(raw, str):
                            for s in re.split(r"[,\s]+", raw):
                                if s.strip():
                                    cand.append(s.strip())

                        for s in cand:
                            if s and not any(s == e[0] for e in entries):
                                entries.append((s, src))
            except OSError:
                continue
    except OSError:
        pass
    return entries

def _windows_version_name(build: int) -> str:
    """Название Windows по номеру сборки (для строки ОС)."""
    if build >= 22000:
        return "Windows 11"
    if build >= 20348:
        return "Windows Server 2022"
    if build >= 10240:
        return "Windows 10"
    if build >= 9600:
        return "Windows 8.1"
    if build >= 9200:
        return "Windows 8"
    return "Windows 7"


def _wsl_config_path() -> str:
    """Путь к .wslconfig на Windows-стороне. USERPROFILE в WSL не прокидывается,
    поэтому: env → /mnt/c/Users/*/.wslconfig → cmd.exe %USERPROFILE%."""
    home = os.environ.get("USERPROFILE", "")
    if not home:
        try:
            out = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"],
                                 capture_output=True, timeout=10).stdout.decode(errors="replace")
            home = out.strip().splitlines()[-1].strip() if out.strip() else ""
        except Exception:
            home = ""
    if home:
        m = re.match(r"^([A-Za-z]):\\(.*)$", home)   # C:\Users\runni -> /mnt/c/Users/runni
        if m:
            return "/mnt/%s/%s/.wslconfig" % (m.group(1).lower(), m.group(2).replace("\\", "/"))
    try:
        for p in glob.glob("/mnt/c/Users/*/.wslconfig"):
            return p
    except Exception:
        pass
    return ""


def _wsl_net_mode() -> str:
    """Режим сети WSL из .wslconfig (Windows-сторона).
    "mirrored + dnsTunneling" / "nat" / "nat + dnsTunneling" и т.п.
    Пусто — .wslconfig не найден/не читается (строку не показываем)."""
    cfg = _wsl_config_path()
    if not cfg:
        return ""
    try:
        with open(cfg, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    in_wsl2, mode, tunnel = False, "nat", False
    for line in text.splitlines():
        s = line.strip()
        if s.lower() == "[wsl2]":
            in_wsl2 = True
            continue
        if in_wsl2 and s.startswith("["):
            in_wsl2 = False
        if not in_wsl2 or "=" not in s:
            continue
        k, _, v = s.partition("=")
        k, v = k.strip().lower(), v.strip().lower()
        if k == "networkingmode":
            mode = v
        elif k == "dnstunneling":
            tunnel = v in ("true", "1", "yes")
    parts = [mode]
    if tunnel:
        parts.append("dnsTunneling")
    return " + ".join(parts)


def _default_route() -> tuple:
    """Маршрут по умолчанию (низшая метрика) из route print: (gateway, iface_ip) или ('', '')."""
    try:
        out = subprocess.run(["route", "print", "0.0.0.0"],
                             capture_output=True, timeout=5).stdout.decode(errors="replace")
    except Exception:
        return "", ""
    cut = out.find("Persistent Routes")
    if cut != -1:
        out = out[:cut]
    best = None
    for line in out.splitlines():
        m = re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$", line)
        if m:
            metric = int(m.group(3))
            if best is None or metric < best[2]:
                best = (m.group(1), m.group(2), metric)
    return (best[0], best[1]) if best else ("", "")


def _netsh_sections() -> List[dict]:
    """Парсинг 'netsh interface ipv4 show config': [{name, has_gw, gw, metric}]."""
    try:
        out = subprocess.run(["netsh", "interface", "ipv4", "show", "config"],
                             capture_output=True, timeout=5).stdout
        text = out.decode("utf-8", errors="replace")
        if "\ufffd" in text:
            text = out.decode("cp866", errors="replace")  # консоль в OEM-кодировке
    except Exception:
        return []
    sections, cur = [], None
    for line in text.splitlines():
        m = re.match(r'^\s*[^:]*?"([^"]+)"\s*$', line)
        if m:
            if cur:
                sections.append(cur)
            cur = {"name": m.group(1), "has_gw": False, "gw": "", "metric": 0}
            continue
        if cur is None:
            continue
        gm = re.search(r"(?i)(?:default\s+)?(?:gateway|шлюз)(?!\s+metric)[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if gm:
            cur["has_gw"], cur["gw"] = True, gm.group(1)
        mt = re.search(r"(?i)metric\s*:\s*(\d+)", line)
        if mt:
            cur["metric"] += int(mt.group(1))
    if cur:
        sections.append(cur)
    return sections


def _active_adapter_guid(live: set, gw: str = "", iface_ip: str = "") -> str:
    """GUID активного адаптера (владелец маршрута по умолчанию).
    Сначала реестровый матч по шлюзу/IP маршрута; если не удалось (VPN-адаптеры
    не пишут IP/шлюз в Tcpip\\Parameters\\Interfaces) — netsh: секция с низшей
    метрикой среди имеющих шлюз. '' — не найден."""
    if not gw and not iface_ip:
        gw, iface_ip = _default_route()
    g = _adapter_for_route(gw, iface_ip, live) if (gw or iface_ip) else ""
    if g:
        return g
    names = _adapter_names()
    by_name = {v: k for k, v in names.items()}
    best = None
    for s in _netsh_sections():
        if not s.get("has_gw"):
            continue
        guid = by_name.get(s["name"])
        if guid and guid not in live:
            continue
        key = (s.get("metric", 0), 0 if s.get("gw") == gw else 1)
        if best is None or key < best[0]:
            best = (key, guid)
    return best[1] if best and best[1] else ""


def _adapter_for_route(gw: str, iface_ip: str, live: set) -> str:
    """GUID живого адаптера маршрута по умолчанию.
    Сначала по шлюзу (DhcpDefaultGateway/DefaultGateway), затем — по IP интерфейса
    маршрута (DhcpIPAddress/IPAddress). '' — не найден."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_BASE) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                sub = winreg.EnumKey(key, i).lower()
                if sub not in live:
                    continue
                try:
                    with winreg.OpenKey(key, sub) as k:
                        if gw:
                            for val in ("DhcpDefaultGateway", "DefaultGateway"):
                                try:
                                    raw = winreg.QueryValueEx(k, val)[0]
                                except OSError:
                                    continue
                                if isinstance(raw, str):
                                    raw = [raw]
                                for entry in raw:
                                    if str(entry).split(",")[0].strip() == gw:
                                        return sub
                        if iface_ip:
                            for val in ("DhcpIPAddress", "IPAddress"):
                                try:
                                    raw = winreg.QueryValueEx(k, val)[0]
                                except OSError:
                                    continue
                                if isinstance(raw, str):
                                    raw = [raw]
                                for entry in raw:
                                    if str(entry).split(",")[0].strip() == iface_ip:
                                        return sub
                except OSError:
                    continue
    except OSError:
        pass
    return ""


def get_system_dns() -> dict:
    """
    DNS системного резолвера.

    Возвращает dict:
      active:       [(сервер, 'static'|'dhcp')] — DNS активного интерфейса
                    (владельца маршрута по умолчанию);
      active_name:  имя активного адаптера (None — не определено);
      other_static: [(сервер, имя_адаптера)] — вручную заданный DNS других
                    живых адаптеров (станет активным при смене сети);
      fallback:     True, если активный интерфейс не определён — тогда active
                    содержит объединённый DNS всех живых адаптеров (как раньше).

    Осиротевшие ключи удалённых адаптеров пропускаются.
    POSIX: /etc/resolv.conf целиком в active (fallback=True).
    """
    res = {"active": [], "active_name": None, "other_static": [],
           "fallback": False, "doh": {}}

    if sys.platform != "win32":
        # WSL: resolv.conf автогенерируется; 10.255.255.254 — DNS-прокси WSL→Windows
        # (не публичный DNS). Другие адреса в WSL/обычном Linux — как обычно.
        is_wsl = False
        try:
            with open("/proc/sys/kernel/osrelease", "r", encoding="utf-8") as f:
                is_wsl = "microsoft" in f.read().lower()
        except OSError:
            pass
        if is_wsl:
            res["wsl_net"] = _wsl_net_mode()
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        if not any(parts[1] == e[0] for e in res["active"]):
                            src = "wsl" if (is_wsl and parts[1] == "10.255.255.254") else "static"
                            res["active"].append((parts[1], src))
        except OSError:
            pass
        res["fallback"] = True
        return res

    build = _windows_build()
    if build:
        res["os"] = f"{_windows_version_name(build)} ({build})"

    res["doh"] = _windows_doh()
    live = _live_adapter_guids()
    if not live:
        return res

    gw, iface_ip = _default_route()
    res["gateway"] = gw
    names = _adapter_names()
    active_guid = _active_adapter_guid(live, gw, iface_ip)

    if active_guid:
        res["active"] = _read_dns_entries(active_guid)
        res["active_name"] = names.get(active_guid)
        res["active_ip"] = iface_ip
        if res["active"]:
            shown = {ip for ip, _ in res["active"]}
            for g in sorted(live):
                if g == active_guid:
                    continue
                for ip, src in _read_dns_entries(g):
                    if ip not in shown:
                        res["other_static"].append((ip, names.get(g) or "{" + g[:8] + "}"))
                        shown.add(ip)
            return res
        # активный интерфейс без DNS-настроек — ниже фолбэк

    res["fallback"] = True
    for g in sorted(live):
        for ip, src in _read_dns_entries(g):
            if not any(ip == e[0] for e in res["active"]):
                res["active"].append((ip, src))
    return res


# Известные обходы DPI: имя для отображения -> подстроки имён процессов.
# Список можно переопределить в config.yml (BYPASS_TOOLS: [[имя, [процессы]], ...]).
_DEFAULT_BYPASS_TOOLS = (
    ("zapret",       ("nfqws", "tpws", "zapret", "dvtws", "dbproxy", "winws")),
    ("GoodbyeDPI",   ("goodbyedpi", "goodbye-dpi", "windivert")),
    ("ByeDPI",       ("byedpi",)),
    ("SpoofDPI",     ("spoofdpi",)),
    ("DPI-Blocker",  ("dpi-blocker", "dpiblocker")),
    ("Green Tunnel", ("greentunnel", "green-tunnel")),
    ("PowerTunnel",  ("powertunnel",)),
    ("Hysteria2",    ("hysteria",)),
    ("TROJAN",       ("trojan",)),
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

_BYPASS_TOOLS = tuple(
    (str(name), tuple(str(p) for p in procs))
    for name, procs in getattr(config, "BYPASS_TOOLS", _DEFAULT_BYPASS_TOOLS)
)


def detect_bypass_tools() -> List[str]:
    """Запущенные локально обходы DPI (по именам процессов). Пусто — ничего нет."""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, errors="replace", timeout=10,
            ).stdout
            names = [l.split('","')[0].strip('"').lower() for l in out.splitlines() if l.strip()]
        else:
            out = subprocess.run(
                ["ps", "-e", "-o", "comm="],
                capture_output=True, text=True, errors="replace", timeout=10,
            ).stdout
            names = [os.path.basename(l.strip()).lower() for l in out.splitlines() if l.strip()]
    except Exception:
        return []
    found: List[str] = []
    for tool, patterns in _BYPASS_TOOLS:
        for pat in patterns:
            # Границы слов: ByeDPI не должен ловиться из GoodbyeDPI.exe
            rx = re.compile(r"(?<![a-z0-9])" + re.escape(pat.lower()))
            if any(rx.search(n) for n in names):
                found.append(tool)
                break
    return found
