import sys

try:
    import yaml
except ImportError:
    print("[!] Ошибка: Не установлена библиотека PyYAML.")
    print("Установите зависимости: pip install -r requirements.txt")
    sys.exit(1)

from pathlib import Path
from typing import Optional


KNOWN_CONFIG_KEYS = {
    "MAX_CONCURRENT", "IP_VERSION", "PROXY_URL", "CONNECT_TIMEOUT", "READ_TIMEOUT",
    "POOL_TIMEOUT", "STUB_IPS_TIMEOUT", "TCP_BLOCK_MIN_KB", "TCP_BLOCK_MAX_KB",
    "FAT_DEFAULT_SNI", "FAT_CONNECT_TIMEOUT", "FAT_READ_TIMEOUT", "USER_AGENT",
    "WSAECONNRESET", "WSAECONNREFUSED", "WSAETIMEDOUT", "WSAENETUNREACH",
    "WSAEHOSTUNREACH", "WSAECONNABORTED", "DNS_CHECK_TIMEOUT", "DNS_PROBE_CONCURRENCY",
    "DNS_CHECK_DOMAINS", "DNS_UDP_SERVERS", "DNS_AVAILABILITY_DOMAINS",
    "DNS_AVAILABILITY_SERVERS", "IP4_LOOKUP_URLS", "IP6_LOOKUP_URLS", "IP_LOOKUP_URLS",
    "CYMRU_DOH_SERVERS", "DNS_UDP_CONCURRENCY", "DNS_DOH_CONCURRENCY",
    "DNS_EGRESS_CONCURRENCY", "DNS_ASN_CONCURRENCY", "ASN_CACHE_FILE",
    "FAT_CHUNKS_COUNT", "FAT_CHUNK_SIZE", "FAT_CHUNK_DELAY", "FAT_RANDOM_POOL_SIZE",
    "SNI_BATCH_SIZE", "SNI_TOP_N", "TELEGRAM_MEDIA_URL", "TELEGRAM_MEDIA_SIZE_MB",
    "TELEGRAM_UPLOAD_IP", "TELEGRAM_UPLOAD_PORT", "TELEGRAM_UPLOAD_SIZE_MB",
    "TELEGRAM_STALL_TIMEOUT", "TELEGRAM_TOTAL_TIMEOUT", "TELEGRAM_DC_PING_TIMEOUT",
    "TELEGRAM_DC_PORT", "TELEGRAM_DCS", "PIN_CACHE_MAX", "PIN_CACHE_TTL",
    "CONCURRENCY_PRESETS", "BYPASS_TOOLS", "DNS_KNOWN_RESOLVER_NAMES", "DEBUG",
    "DNS_STUB_THRESHOLD", "DNS_AVAILABILITY_TIMEOUT"
}

PROTECTED_CONFIG_KEYS = {
    "CONFIG_LOAD_ERROR", "CONFIG_WARNINGS", "KNOWN_CONFIG_KEYS",
    "PROTECTED_CONFIG_KEYS", "VALIDATORS", "load_config", "get_config_path"
}

# Значения по умолчанию на случай отсутствия config.yml
MAX_CONCURRENT = 50
IP_VERSION = "ipv4"
PROXY_URL = None
CONNECT_TIMEOUT = 8.0
READ_TIMEOUT = 8.0
POOL_TIMEOUT = 2.0
STUB_IPS_TIMEOUT = 5.0
TCP_BLOCK_MIN_KB = 12
TCP_BLOCK_MAX_KB = 36
FAT_DEFAULT_SNI = "example.com"
FAT_CONNECT_TIMEOUT = 8.0
FAT_READ_TIMEOUT = 12.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
WSAECONNRESET = 10054
WSAECONNREFUSED = 10061
WSAETIMEDOUT = 10060
WSAENETUNREACH = 10051
WSAEHOSTUNREACH = 10065
WSAECONNABORTED = 10053
DNS_CHECK_TIMEOUT = 5.0
DNS_AVAILABILITY_TIMEOUT = 5.0
DNS_PROBE_CONCURRENCY = 20
DNS_CHECK_DOMAINS = []
DNS_UDP_SERVERS = []
DNS_AVAILABILITY_DOMAINS = ["vk.ru", "gosuslugi.ru"]
DNS_AVAILABILITY_SERVERS = []
DNS_UDP_CONCURRENCY = 15
DNS_DOH_CONCURRENCY = 20
DNS_EGRESS_CONCURRENCY = 10
DNS_ASN_CONCURRENCY = 8
ASN_CACHE_FILE = None
FAT_CHUNKS_COUNT = 10
FAT_CHUNK_SIZE = 4000
FAT_CHUNK_DELAY = 0.05
FAT_RANDOM_POOL_SIZE = 100000
SNI_BATCH_SIZE = 5
SNI_TOP_N = 3
TELEGRAM_MEDIA_URL = "https://telegram.org/img/Telegram200million.png"
TELEGRAM_MEDIA_SIZE_MB = 30.97
TELEGRAM_UPLOAD_IP = "149.154.167.220"
TELEGRAM_UPLOAD_PORT = 443
TELEGRAM_UPLOAD_SIZE_MB = 10
TELEGRAM_STALL_TIMEOUT = 10.0
TELEGRAM_TOTAL_TIMEOUT = 60.0
TELEGRAM_DC_PING_TIMEOUT = 5.0
TELEGRAM_DC_PORT = 443
TELEGRAM_DCS = [
    ["149.154.175.53",  "DC1"],
    ["149.154.167.51",  "DC2"],
    ["149.154.175.100", "DC3"],
    ["149.154.167.91",  "DC4"],
    ["91.108.56.130",   "DC5"],
]
PIN_CACHE_MAX = 256
PIN_CACHE_TTL = 3600.0
CONCURRENCY_PRESETS = [1, 5, 20, 50, 100]
CYMRU_DOH_SERVERS = (
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://common.dot.dns.yandex.net/dns-query",
)
IP4_LOOKUP_URLS = (
    "https://api4.ipify.org", "https://api.ipify.org",
    "https://v4.ident.me", "https://ipv4.icanhazip.com",
)
IP6_LOOKUP_URLS = (
    "https://api64.ipify.org", "https://icanhazip.com",
    "https://ifconfig.me/ip", "https://v6.ident.me",
)
IP_LOOKUP_URLS = IP4_LOOKUP_URLS
BYPASS_TOOLS = []
DNS_KNOWN_RESOLVER_NAMES = []
DNS_STUB_THRESHOLD = 2
DEBUG = False
CONFIG_LOAD_ERROR = None
CONFIG_WARNINGS = []


def _validate_int_range(min_v: int, max_v: Optional[int] = None):
    def validator(v):
        if not isinstance(v, int) or isinstance(v, bool):
            return False, "должно быть целым числом"
        if v < min_v:
            return False, f"должно быть >= {min_v}"
        if max_v is not None and v > max_v:
            return False, f"должно быть <= {max_v}"
        return True, ""
    return validator


def _validate_float_pos():
    def validator(v):
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
            return False, "должно быть положительным числом (> 0)"
        return True, ""
    return validator


VALIDATORS = {
    "MAX_CONCURRENT": _validate_int_range(1, 1000),
    "IP_VERSION": lambda v: (True, "") if v in ("ipv4", "ipv6") else (False, "допустимы только 'ipv4' или 'ipv6'"),
    "PROXY_URL": lambda v: (True, "") if v is None or isinstance(v, str) else (False, "должно быть строкой или null"),
    "CONNECT_TIMEOUT": _validate_float_pos(),
    "READ_TIMEOUT": _validate_float_pos(),
    "POOL_TIMEOUT": _validate_float_pos(),
    "STUB_IPS_TIMEOUT": _validate_float_pos(),
    "TCP_BLOCK_MIN_KB": _validate_int_range(1),
    "TCP_BLOCK_MAX_KB": _validate_int_range(1),
    "FAT_DEFAULT_SNI": lambda v: (True, "") if isinstance(v, str) and v else (False, "должно быть непустой строкой"),
    "FAT_CONNECT_TIMEOUT": _validate_float_pos(),
    "FAT_READ_TIMEOUT": _validate_float_pos(),
    "FAT_CHUNKS_COUNT": _validate_int_range(1, 100),
    "FAT_CHUNK_SIZE": _validate_int_range(100, 1_000_000),
    "FAT_CHUNK_DELAY": lambda v: (True, "") if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else (False, "должно быть неотрицательным числом"),
    "FAT_RANDOM_POOL_SIZE": _validate_int_range(1000, 10_000_000),
    "SNI_BATCH_SIZE": _validate_int_range(1, 50),
    "SNI_TOP_N": _validate_int_range(1, 20),
    "USER_AGENT": lambda v: (True, "") if isinstance(v, str) and v else (False, "должно быть непустой строкой"),
    "DNS_CHECK_TIMEOUT": _validate_float_pos(),
    "DNS_AVAILABILITY_TIMEOUT": _validate_float_pos(),
    "DNS_PROBE_CONCURRENCY": _validate_int_range(1, 200),
    "DNS_UDP_CONCURRENCY": _validate_int_range(1, 200),
    "DNS_DOH_CONCURRENCY": _validate_int_range(1, 200),
    "DNS_EGRESS_CONCURRENCY": _validate_int_range(1, 200),
    "DNS_ASN_CONCURRENCY": _validate_int_range(1, 100),
    "DEBUG": lambda v: (True, "") if isinstance(v, bool) else (False, "должно быть true или false"),
    "CONCURRENCY_PRESETS": lambda v: (True, "") if isinstance(v, list) and all(isinstance(x, int) and x > 0 for x in v) else (False, "должно быть списком положительных целых чисел"),
    "PIN_CACHE_MAX": _validate_int_range(1, 10000),
    "PIN_CACHE_TTL": _validate_float_pos(),
    "TELEGRAM_MEDIA_SIZE_MB": _validate_float_pos(),
    "TELEGRAM_UPLOAD_SIZE_MB": _validate_float_pos(),
    "TELEGRAM_STALL_TIMEOUT": _validate_float_pos(),
    "TELEGRAM_TOTAL_TIMEOUT": _validate_float_pos(),
    "TELEGRAM_DC_PING_TIMEOUT": _validate_float_pos(),
    "TELEGRAM_DC_PORT": _validate_int_range(1, 65535),
    "DNS_STUB_THRESHOLD": _validate_int_range(1, 50),
    "BYPASS_TOOLS": lambda v: (True, "") if isinstance(v, list) and all(isinstance(x, (list, tuple)) and len(x) >= 2 for x in v) else (False, "должно быть списком пар [имя, [процессы]]"),
    "DNS_AVAILABILITY_SERVERS": lambda v: (True, "") if isinstance(v, list) and all(isinstance(x, (list, tuple)) and len(x) >= 3 for x in v) else (False, "должно быть списком [адрес, имя, тип]"),
    "TELEGRAM_DCS": lambda v: (True, "") if isinstance(v, list) and all(isinstance(x, (list, tuple)) and len(x) >= 2 for x in v) else (False, "должно быть списком пар [ip, имя]"),
}

def get_config_path() -> Path:
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).parent
        external = exe_dir / "config.yml"
        bundled = Path(getattr(sys, '_MEIPASS', exe_dir)) / "config.yml"
        return external if external.exists() else bundled
    base_dir = Path(__file__).resolve().parent.parent
    return base_dir / "config.yml"


def load_config(path: Optional[Path] = None) -> bool:
    global CONFIG_LOAD_ERROR
    CONFIG_WARNINGS.clear()
    yml_path = path or get_config_path()
    if not yml_path.exists():
        CONFIG_LOAD_ERROR = f"Файл конфигурации не найден: {yml_path}"
        return False

    try:
        with open(yml_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)

        if not isinstance(config_data, dict):
            CONFIG_LOAD_ERROR = "Файл config.yml пуст или имеет неверный формат."
            return False

        unknown_keys = set(config_data.keys()) - KNOWN_CONFIG_KEYS
        if unknown_keys:
            warning_msg = f"Неизвестные параметры в config.yml: {', '.join(sorted(unknown_keys))}"
            CONFIG_WARNINGS.append(warning_msg)

        for key, value in config_data.items():
            if not key.isupper() or key in PROTECTED_CONFIG_KEYS or key not in KNOWN_CONFIG_KEYS:
                continue
            validator = VALIDATORS.get(key)
            if validator:
                is_valid, err = validator(value)
                if not is_valid:
                    CONFIG_WARNINGS.append(f"Недопустимое значение {key}: {err}. Используется значение по умолчанию.")
                    continue
            globals()[key] = value
        if globals().get("TCP_BLOCK_MIN_KB", 12) > globals().get("TCP_BLOCK_MAX_KB", 36):
            CONFIG_WARNINGS.append("TCP_BLOCK_MIN_KB больше TCP_BLOCK_MAX_KB. Сброшены на значения по умолчанию (12 и 36).")
            globals()["TCP_BLOCK_MIN_KB"] = 12
            globals()["TCP_BLOCK_MAX_KB"] = 36

        CONFIG_LOAD_ERROR = None
        return True

    except Exception as e:
        CONFIG_LOAD_ERROR = f"Ошибка при чтении config.yml: {e}"
        return False


# Автозагрузка конфигурации при импорте модуля
load_config()
