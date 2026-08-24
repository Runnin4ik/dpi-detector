#!/usr/bin/env python3
"""
Сверка DoH-эндпоинтов из config.yml внешними инструментами (dig / curl).

Для каждого doh_wire-эндпоинта из DNS_AVAILABILITY_SERVERS делает один запрос
и печатает одну строку результата. Служит для перекрёстной проверки результатов
dpi_detector обычными программами.

Бэкенды (в порядке приоритета):
  dig  (BIND >= 9.18) : dig +https=<url> — полноценный RFC 8484
  curl (--doh-url)    : резолвит адрес тестового домена через указанный DoH

Использование:
  python check_doh.py [домен]
  python check_doh.py --udp          # добавить и UDP-серверы (только dig)
"""
import os
import re
import argparse
import shutil
import subprocess
import sys

import yaml


def load_doh_endpoints():
    with open("config.yml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    servers = cfg.get("DNS_AVAILABILITY_SERVERS", [])
    domain_cfg = cfg.get("DNS_AVAILABILITY_DOMAINS") or cfg.get("DNS_CHECK_DOMAINS") or []
    doh = [(n, u) for u, n, k in servers if k == "doh_wire"]
    udp = [(n, a) for a, n, k in servers if k == "udp"]
    return doh, udp, domain_cfg


def probe_dig(url: str, domain: str, timeout: int):
    """Возвращает (ok, краткий результат)."""
    cmd = [
        "dig", f"+https={url}", f"+time={timeout}", "+tries=1",
        "+short", "A", domain,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    out = [l.strip() for l in p.stdout.splitlines() if l.strip()]
    ips = [l for l in out if l.replace(".", "").isdigit()]
    if ips:
        return True, ", ".join(ips[:2])
    err = (p.stderr or "").strip().splitlines()
    reason = err[-1].split(";")[-1].strip() if err else f"exit={p.returncode}"
    return False, f"FAIL ({reason[:60]})"

DOGGO = None  # путь до doggo.exe, определяется в main()


def probe_doggo(url: str, domain: str, timeout: int):
    """doggo (Go, RFC 8484) — не требует HTTP/2 в системных библиотеках."""
    cmd = [DOGGO, domain, "A", f"@{url}", "--short", "--timeout", f"{timeout}s"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    ips = [l.strip() for l in p.stdout.splitlines()
           if l.strip() and l.strip().replace(".", "").isdigit()]
    if ips and p.returncode == 0:
        return True, ", ".join(ips[:2])
    err = (p.stderr or "").strip().splitlines()
    reason = ""
    for line in reversed(err):
        m = re.search(r'msg="([^"]+)"', line)
        if not m:
            m = re.search(r"msg=([^\s]+)", line)
        if m:
            reason = m.group(1)
            break
    if not reason:
        reason = f"exit={p.returncode}"
    return False, f"FAIL ({reason[:60]})"


def probe_curl(url: str, domain: str, timeout: int):
    """
    curl сам ходит на DoH-сервер и получает через него IP целевого домена.
    %{remote_ip} = адрес, который вернул проверяемый DoH.
    """
    cmd = [
        "curl", "-s", "-o", "NUL" if sys.platform == "win32" else "/dev/null",
        "--doh-url", url,
        "--connect-timeout", str(timeout), "-m", str(timeout + 3),
        "-w", "%{remote_ip}|%{http_code}",
        f"https://{domain}",
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    out = p.stdout.strip()
    if "|" not in out:
        return False, "FAIL (no answer)"
    ip, code = out.split("|", 1)
    if ip and ip != "0.0.0.0":
        # HTTPS до цели мог не завершиться — но нам важен именно ответ DoH
        if code in ("000", ""):
            return True, f"{ip} (TLS до цели не прошёл, но DoH ответил)"
        return True, ip
    return False, "FAIL (DoH не ответил)"


def main():
    ap = argparse.ArgumentParser(description="Проверка DoH-эндпоинтов из config.yml: dig/doggo/curl")
    ap.add_argument("domain", nargs="?", help="домен для теста (по умолчанию из config.yml)")
    ap.add_argument("--udp", action="store_true", help="проверить также UDP-серверы (только dig)")
    ap.add_argument("--backend", choices=["auto", "dig", "doggo", "curl"], default="auto")
    ap.add_argument("--timeout", type=int, default=5)
    args = ap.parse_args()

    doh, udp, domains_cfg = load_doh_endpoints()
    domain = args.domain or (domains_cfg[0] if domains_cfg else "example.com")

    global DOGGO
    for cand in ("doggo", r"C:\Users\runnin\bin\doggo.exe"):
        found = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if found:
            DOGGO = found
            break

    def _dig_supports_doh():
        """DoH (+https) появился в BIND 9.18; choco ставит устаревший 9.16."""
        try:
            ver = subprocess.run(["dig", "-v"], capture_output=True, text=True)
            m = re.search(r"9\.(\d+)\.", ver.stdout + ver.stderr)
            return bool(m) and int(m.group(1)) >= 18
        except Exception:
            return False

    if args.backend == "auto":
        if shutil.which("dig") and _dig_supports_doh():
            backend = "dig"
        elif DOGGO:
            backend = "doggo"
        else:
            backend = "curl"
    else:
        backend = args.backend

    if backend == "dig" and not shutil.which("dig"):
        sys.exit("dig не найден в PATH")
    if backend == "doggo" and not DOGGO:
        sys.exit(
            "doggo не найден. Скачай с https://github.com/mr-karan/doggo/releases\n"
            "(doggo-windows-x86_64.zip) и положи doggo.exe в PATH или ~/bin."
        )
    if backend == "curl":
        # Системный Windows-curl без HTTP/2: серверы, требующие H2, дадут ложный FAIL.
        ver = subprocess.run(["curl", "--version"], capture_output=True, text=True).stdout
        if "HTTP2" not in ver.splitlines()[0]:
            print(
                "[!] ВНИМАНИЕ: этот curl без HTTP/2 — серверы, требующие H2 "
                "(Quad9, Cloudflare и др.), покажут ложный FAIL.\n"
                "    Лучше поставь doggo: https://github.com/mr-karan/doggo/releases\n"
            )

    probe_fn = {"dig": probe_dig, "doggo": probe_doggo, "curl": probe_curl}[backend]
    targets = list(doh) + ([(n, a) for a, n in udp] if args.udp and backend == "dig" else [])

    print(f"Бэкенд: {backend} | домен: {domain} | таймаут: {args.timeout}s")
    print("-" * 78)
    for name, addr in targets:
        ok, info = probe_fn(addr, domain, args.timeout)
        mark = "OK  " if ok else "FAIL"
        print(f"{mark} {name:<16} {addr:<52} {info}")
    print("-" * 78)


if __name__ == "__main__":
    main()
