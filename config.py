import os
import sys
"""
Конфигурация DPI Detector
"""

# === Основные настройки ===
MAX_CONCURRENT = 100

# === Таймауты ===
TIMEOUT = 7.0

# === TCP блокировка ===
TCP_BLOCK_MIN_KB = 1
TCP_BLOCK_MAX_KB = 69
FAT_DEFAULT_SNI = "example.com"
FAT_CONNECT_TIMEOUT = 8.0
FAT_READ_TIMEOUT = 12.0

# === Отображение ===
BODY_INSPECT_LIMIT = 8192

# === User Agent ===
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

# === Маркеры блокировок HTTP ===
BLOCK_MARKERS = [
    "lawfilter", "warning.rt.ru", "blocked", "access-denied",
    "eais", "zapret-info", "rkn.gov.ru", "mvd.ru"
]

BODY_BLOCK_MARKERS = [
    "blocked", "заблокирован", "запрещён", "запрещен", "ограничен",
    "единый реестр", "роскомнадзор", "rkn.gov.ru",
    "nap.gov.ru", "eais.rkn.gov.ru", "warning.rt.ru",
    "blocklist", "решению суда",
]

# === Windows-специфичные errno коды ===
WSAECONNRESET = 10054
WSAECONNREFUSED = 10061
WSAETIMEDOUT = 10060
WSAENETUNREACH = 10051
WSAEHOSTUNREACH = 10065
WSAECONNABORTED = 10053
WSAENETDOWN = 10050
WSAEACCES = 10013

# === DNS проверка ===
DNS_CHECK_ENABLED = True
DNS_CHECK_TIMEOUT = 5.0
DNS_CHECK_DOMAINS = [
    "rutor.info",
    "ej.ru",
    "flibusta.is",
    "clubtone.do.am",
    "rezka.ag",
    "shikimori.one",
    "www.lgbt.org.ua",
    "www.fastmail.com",
    "newtime.ua",
    "fast-die.kiev.ua",
    "church.ua",
]

""" Доп домены на которые провайдер выдает NX
    "www.youtube.com",
    "youtube.com",
    "m.youtube.com",
    "limetorrents.pro",
    "www.whatsapp.com",
"""

DNS_UDP_SERVERS = [
    ("8.8.8.8",        "Google"),
    ("1.1.1.1",        "Cloudflare"),
    ("9.9.9.9",        "Quad9"),
    ("94.140.14.14",   "AdGuard"),
    ("77.88.8.8",      "Yandex"),
    ("223.5.5.5",      "Alibaba"),
    ("208.67.222.222", "OpenDNS"),    # Cisco
    ("76.76.2.0",      "ControlD"),
    ("194.242.2.2",    "Mullvad"),
]

DNS_DOH_SERVERS = [
   ("https://8.8.8.8/resolve",              "Google"),
   ("https://dns.google/resolve",           "Google"),
   ("https://1.1.1.1/dns-query",            "Cloudflare"),
   ("https://cloudflare-dns.com/dns-query", "Cloudflare"),
   ("https://one.one.one.one/dns-query",    "Cloudflare"),
   ("https://dns.adguard-dns.com/resolve",  "AdGuard"),
   ("https://dns.alidns.com/resolve",       "Alibaba"),
]

# хак для переопределения дефолтного config.py
if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
else:
    exe_dir = os.path.dirname(os.path.abspath(__file__))

external_config_path = os.path.join(exe_dir, "config.py")

if os.path.exists(external_config_path) and os.path.abspath(__file__) != external_config_path:
    try:
        with open(external_config_path, 'r', encoding='utf-8') as ext_f:
            exec(ext_f.read(), globals())
    except Exception as e:
        print(f"[!] Ошибка при загрузке внешнего config.py: {e}")
        print("Нажмите любую клавишу для выхода...")

        try:
            import msvcrt
            msvcrt.getch()
        except ImportError:
            input()

        sys.exit(1)