use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

fn d_max_concurrent() -> usize { 50 }
fn d_ip_version() -> String { "ipv4".to_string() }
fn d_connect_timeout() -> f64 { 8.0 }
fn d_read_timeout() -> f64 { 8.0 }
fn d_pool_timeout() -> f64 { 2.0 }
fn d_stub_ips_timeout() -> f64 { 5.0 }
fn d_tcp_block_min_kb() -> u64 { 12 }
fn d_tcp_block_max_kb() -> u64 { 36 }
fn d_fat_default_sni() -> String { "example.com".to_string() }
fn d_fat_connect_timeout() -> f64 { 8.0 }
fn d_fat_read_timeout() -> f64 { 12.0 }
fn d_user_agent() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36".to_string()
}
fn d_dns_check_timeout() -> f64 { 5.0 }
fn d_dns_availability_timeout() -> f64 { 5.0 }
fn d_dns_probe_concurrency() -> usize { 20 }
fn d_dns_udp_concurrency() -> usize { 15 }
fn d_dns_doh_concurrency() -> usize { 20 }
fn d_dns_egress_concurrency() -> usize { 10 }
fn d_dns_asn_concurrency() -> usize { 8 }
fn d_dns_stub_threshold() -> u32 { 2 }
fn d_fat_chunks_count() -> usize { 10 }
fn d_fat_chunk_size() -> usize { 4000 }
fn d_fat_chunk_delay() -> f64 { 0.05 }
fn d_fat_random_pool_size() -> usize { 100000 }
fn d_sni_batch_size() -> usize { 5 }
fn d_sni_top_n() -> usize { 3 }
fn d_telegram_media_url() -> String {
    "https://telegram.org/img/Telegram200million.png".to_string()
}
fn d_telegram_media_size_mb() -> f64 { 30.97 }
fn d_telegram_upload_ip() -> String { "149.154.167.220".to_string() }
fn d_telegram_upload_port() -> u16 { 443 }
fn d_telegram_upload_size_mb() -> f64 { 10.0 }
fn d_telegram_stall_timeout() -> f64 { 10.0 }
fn d_telegram_total_timeout() -> f64 { 60.0 }
fn d_telegram_dc_ping_timeout() -> f64 { 5.0 }
fn d_telegram_dc_port() -> u16 { 443 }
fn d_domains_file() -> String { "domains.txt".to_string() }
fn d_tcp16_file() -> String { "tcp16.json".to_string() }
fn d_whitelist_sni_file() -> String { "whitelist_sni.txt".to_string() }

fn d_dns_check_domains() -> Vec<String> {
    vec![
        "rutor.info".to_string(),
        "flibusta.is".to_string(),
        "clubtone.do.am".to_string(),
        "rezka.ag".to_string(),
        "shikimori.one".to_string(),
    ]
}

fn d_dns_udp_servers() -> Vec<Vec<String>> {
    vec![
        vec!["8.8.8.8".to_string(), "Google".to_string()],
        vec!["1.1.1.1".to_string(), "Cloudflare".to_string()],
        vec!["9.9.9.9".to_string(), "Quad9".to_string()],
        vec!["94.140.14.14".to_string(), "AdGuard".to_string()],
        vec!["77.88.8.8".to_string(), "Yandex".to_string()],
        vec!["223.5.5.5".to_string(), "Alibaba".to_string()],
        vec!["208.67.222.222".to_string(), "OpenDNS".to_string()],
        vec!["76.76.2.0".to_string(), "ControlD".to_string()],
        vec!["194.242.2.2".to_string(), "Mullvad".to_string()],
        vec!["185.228.168.9".to_string(), "CleanBrowsing".to_string()],
        vec!["76.223.122.150".to_string(), "NextDNS".to_string()],
        vec!["185.222.222.222".to_string(), "DNS.SB".to_string()],
        vec!["176.9.93.198".to_string(), "dnsforge".to_string()],
    ]
}

fn d_dns_availability_domains() -> Vec<String> {
    vec!["vk.ru".to_string(), "gosuslugi.ru".to_string()]
}

fn d_cymru_doh_servers() -> Vec<String> {
    vec![
        "https://dns.google/dns-query".to_string(),
        "https://cloudflare-dns.com/dns-query".to_string(),
        "https://common.dot.dns.yandex.net/dns-query".to_string(),
        "https://dns.nextdns.io/dns-query".to_string(),
        "https://dns.opendns.com/dns-query".to_string(),
    ]
}

fn d_ip4_lookup_urls() -> Vec<String> {
    vec![
        // NOTE: api4/api.ipify.org removed: several RF ISPs spoof their DNS
        // to bogus 8.x addresses, so these endpoints can never win the race.
        // Uncomment them back on clean networks if needed.
        "https://v4.ident.me".to_string(),
        "https://ipv4.icanhazip.com".to_string(),
        // Last-resort plain HTTP: proven reachable on lines where all HTTPS
        // lookups are SNI-filtered (returns caller IP as plaintext).
        "http://v4.ident.me".to_string(),
    ]
}

fn d_ip6_lookup_urls() -> Vec<String> {
    vec![
        "https://api64.ipify.org".to_string(),
        "https://icanhazip.com".to_string(),
        "https://ifconfig.me/ip".to_string(),
        "https://v6.ident.me".to_string(),
    ]
}

fn d_concurrency_presets() -> Vec<usize> {
    vec![1, 5, 20, 50, 100]
}

fn d_bypass_tools() -> Vec<Vec<serde_yaml::Value>> {
    // (name, [patterns]) — defaults mirror config.yml BYPASS_TOOLS
    let raw = r#"
- ["zapret", ["nfqws", "tpws", "zapret", "dvtws", "dbproxy", "winws"]]
- ["GoodbyeDPI", ["goodbyedpi", "goodbye-dpi", "windivert"]]
- ["ByeDPI", ["byedpi"]]
- ["SpoofDPI", ["spoofdpi"]]
- ["DPI-Blocker", ["dpi-blocker", "dpiblocker"]]
- ["Green Tunnel", ["greentunnel", "green-tunnel"]]
- ["PowerTunnel", ["powertunnel"]]
- ["Hysteria2", ["hysteria"]]
- ["TROJAN", ["trojan"]]
- ["NaiveProxy", ["naive"]]
- ["Wstunnel", ["wstunnel"]]
- ["UDP2RAW", ["udp2raw"]]
- ["dnscrypt-proxy", ["dnscrypt-proxy"]]
- ["xray", ["xray"]]
- ["FlClashX", ["flclashx", "flclashcore"]]
- ["AmneziaWG", ["amneziawg"]]
- ["Clash", ["mihomo", "clash-meta", "clash-verge", "clash_verge", "verge-mihomo"]]
- ["sing-box", ["sing-box"]]
- ["Hiddify", ["hiddify"]]
- ["Tailscale", ["tailscale"]]
- ["ZeroTier", ["zerotier"]]
- ["Mullvad", ["mullvad"]]
- ["WARP", ["warp-svc", "cloudflarewarp"]]
- ["NordVPN", ["nordvpn"]]
"#;
    serde_yaml::from_str(raw).unwrap_or_default()
}

fn d_dns_known_resolver_names() -> Vec<String> {
    vec![
        // Egress-ASN tokens observed on real (non-hijacked) answers.
        "google", "cloudflarenet", "i3dnet", "cdn77", "alibaba-cn-net",
        "as-vultr", "cdnext", "xtom", "tencent-net-ap-cn", "misaka-cis-as",
        "as-anexia", "ru-jsciot", "yandex", "cisco", "woodynet",
        // Resolver-brand tokens, parity with Python _KNOWN_RESOLVER_NAME_TOKENS:
        // a whitelisted org is always green, even if a sibling endpoint
        // of the same brand was hijacked elsewhere.
        // NOTE: Python's "t2" token deliberately omitted (2-char substring
        // matches too broadly and would whitelist hijacker ASNs).
        "cloudflare", "quad9", "adguard", "opendns", "cleanbrowsing",
        "nextdns", "controld", "mullvad", "dns0", "ahadns",
        "comss", "geohide",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

fn d_telegram_dcs() -> Vec<Vec<String>> {
    vec![
        vec!["149.154.175.53".to_string(), "DC1".to_string()],
        vec!["149.154.167.51".to_string(), "DC2".to_string()],
        vec!["149.154.175.100".to_string(), "DC3".to_string()],
        vec!["149.154.167.91".to_string(), "DC4".to_string()],
        vec!["91.108.56.130".to_string(), "DC5".to_string()],
    ]
}

/// One DNS availability server entry: [address, name, type, port?].
/// Types: "udp", "doh_json", "doh_wire", "dot".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAvailServer {
    pub addr: String,
    pub name: String,
    pub kind: String,
    pub port: u16,
}

impl DnsAvailServer {
    pub fn default_port(kind: &str) -> u16 {
        match kind {
            "udp" => 53,
            "dot" => 853,
            _ => 443,
        }
    }
}

fn yaml_str(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    #[serde(default = "d_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "d_ip_version")]
    pub ip_version: String,
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// Legacy alias: CLI --proxy writes here; mirrors proxy_url.
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default = "d_connect_timeout")]
    pub connect_timeout: f64,
    #[serde(default = "d_read_timeout")]
    pub read_timeout: f64,
    #[serde(default = "d_pool_timeout")]
    pub pool_timeout: f64,
    #[serde(default = "d_stub_ips_timeout")]
    pub stub_ips_timeout: f64,
    #[serde(default = "d_tcp_block_min_kb")]
    pub tcp_block_min_kb: u64,
    #[serde(default = "d_tcp_block_max_kb")]
    pub tcp_block_max_kb: u64,
    #[serde(default = "d_fat_default_sni")]
    pub fat_default_sni: String,
    #[serde(default = "d_fat_connect_timeout")]
    pub fat_connect_timeout: f64,
    #[serde(default = "d_fat_read_timeout")]
    pub fat_read_timeout: f64,
    #[serde(default = "d_user_agent")]
    pub user_agent: String,
    #[serde(default = "d_dns_check_timeout")]
    pub dns_check_timeout: f64,
    #[serde(default = "d_dns_availability_timeout")]
    pub dns_availability_timeout: f64,
    #[serde(default = "d_dns_probe_concurrency")]
    pub dns_probe_concurrency: usize,
    #[serde(default = "d_dns_check_domains")]
    pub dns_check_domains: Vec<String>,
    #[serde(default = "d_dns_udp_servers")]
    pub dns_udp_servers: Vec<Vec<String>>,
    #[serde(default = "d_dns_availability_domains")]
    pub dns_availability_domains: Vec<String>,
    /// Raw server rows: [addr, name, kind, port?]. Parsed via `availability_servers()`.
    #[serde(default)]
    pub dns_availability_servers: Vec<Vec<serde_yaml::Value>>,
    #[serde(default = "d_dns_udp_concurrency")]
    pub dns_udp_concurrency: usize,
    #[serde(default = "d_dns_doh_concurrency")]
    pub dns_doh_concurrency: usize,
    #[serde(default = "d_dns_egress_concurrency")]
    pub dns_egress_concurrency: usize,
    #[serde(default = "d_dns_asn_concurrency")]
    pub dns_asn_concurrency: usize,
    #[serde(default = "d_dns_stub_threshold")]
    pub dns_stub_threshold: u32,
    #[serde(default = "d_fat_chunks_count")]
    pub fat_chunks_count: usize,
    #[serde(default = "d_fat_chunk_size")]
    pub fat_chunk_size: usize,
    #[serde(default = "d_fat_chunk_delay")]
    pub fat_chunk_delay: f64,
    #[serde(default = "d_fat_random_pool_size")]
    pub fat_random_pool_size: usize,
    #[serde(default = "d_sni_batch_size")]
    pub sni_batch_size: usize,
    #[serde(default = "d_sni_top_n")]
    pub sni_top_n: usize,
    #[serde(default = "d_telegram_media_url")]
    pub telegram_media_url: String,
    #[serde(default = "d_telegram_media_size_mb")]
    pub telegram_media_size_mb: f64,
    #[serde(default = "d_telegram_upload_ip")]
    pub telegram_upload_ip: String,
    #[serde(default = "d_telegram_upload_port")]
    pub telegram_upload_port: u16,
    #[serde(default = "d_telegram_upload_size_mb")]
    pub telegram_upload_size_mb: f64,
    #[serde(default = "d_telegram_stall_timeout")]
    pub telegram_stall_timeout: f64,
    #[serde(default = "d_telegram_total_timeout")]
    pub telegram_total_timeout: f64,
    #[serde(default = "d_telegram_dc_ping_timeout")]
    pub telegram_dc_ping_timeout: f64,
    #[serde(default = "d_telegram_dc_port")]
    pub telegram_dc_port: u16,
    #[serde(default = "d_telegram_dcs")]
    pub telegram_dcs: Vec<Vec<String>>,
    #[serde(default = "d_concurrency_presets")]
    pub concurrency_presets: Vec<usize>,
    /// Raw rows: [name, [patterns]]. Parsed via `bypass_tools()`.
    #[serde(default = "d_bypass_tools")]
    pub bypass_tools_raw: Vec<Vec<serde_yaml::Value>>,
    #[serde(default = "d_dns_known_resolver_names")]
    pub dns_known_resolver_names: Vec<String>,
    #[serde(default = "d_cymru_doh_servers")]
    pub cymru_doh_servers: Vec<String>,
    #[serde(default = "d_ip4_lookup_urls")]
    pub ip4_lookup_urls: Vec<String>,
    #[serde(default = "d_ip6_lookup_urls")]
    pub ip6_lookup_urls: Vec<String>,
    #[serde(default = "d_domains_file")]
    pub domains_file: String,
    #[serde(default = "d_tcp16_file")]
    pub tcp16_file: String,
    #[serde(default = "d_whitelist_sni_file")]
    pub whitelist_sni_file: String,
    #[serde(default)]
    pub debug: bool,
    #[serde(skip)]
    pub config_load_error: Option<String>,
    #[serde(skip)]
    pub config_warnings: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            max_concurrent: d_max_concurrent(),
            ip_version: d_ip_version(),
            proxy_url: None,
            proxy: None,
            connect_timeout: d_connect_timeout(),
            read_timeout: d_read_timeout(),
            pool_timeout: d_pool_timeout(),
            stub_ips_timeout: d_stub_ips_timeout(),
            tcp_block_min_kb: d_tcp_block_min_kb(),
            tcp_block_max_kb: d_tcp_block_max_kb(),
            fat_default_sni: d_fat_default_sni(),
            fat_connect_timeout: d_fat_connect_timeout(),
            fat_read_timeout: d_fat_read_timeout(),
            user_agent: d_user_agent(),
            dns_check_timeout: d_dns_check_timeout(),
            dns_availability_timeout: d_dns_availability_timeout(),
            dns_probe_concurrency: d_dns_probe_concurrency(),
            dns_check_domains: d_dns_check_domains(),
            dns_udp_servers: d_dns_udp_servers(),
            dns_availability_domains: d_dns_availability_domains(),
            dns_availability_servers: Vec::new(),
            dns_udp_concurrency: d_dns_udp_concurrency(),
            dns_doh_concurrency: d_dns_doh_concurrency(),
            dns_egress_concurrency: d_dns_egress_concurrency(),
            dns_asn_concurrency: d_dns_asn_concurrency(),
            dns_stub_threshold: d_dns_stub_threshold(),
            fat_chunks_count: d_fat_chunks_count(),
            fat_chunk_size: d_fat_chunk_size(),
            fat_chunk_delay: d_fat_chunk_delay(),
            fat_random_pool_size: d_fat_random_pool_size(),
            sni_batch_size: d_sni_batch_size(),
            sni_top_n: d_sni_top_n(),
            telegram_media_url: d_telegram_media_url(),
            telegram_media_size_mb: d_telegram_media_size_mb(),
            telegram_upload_ip: d_telegram_upload_ip(),
            telegram_upload_port: d_telegram_upload_port(),
            telegram_upload_size_mb: d_telegram_upload_size_mb(),
            telegram_stall_timeout: d_telegram_stall_timeout(),
            telegram_total_timeout: d_telegram_total_timeout(),
            telegram_dc_ping_timeout: d_telegram_dc_ping_timeout(),
            telegram_dc_port: d_telegram_dc_port(),
            telegram_dcs: d_telegram_dcs(),
            concurrency_presets: d_concurrency_presets(),
            bypass_tools_raw: d_bypass_tools(),
            dns_known_resolver_names: d_dns_known_resolver_names(),
            cymru_doh_servers: d_cymru_doh_servers(),
            ip4_lookup_urls: d_ip4_lookup_urls(),
            ip6_lookup_urls: d_ip6_lookup_urls(),
            domains_file: d_domains_file(),
            tcp16_file: d_tcp16_file(),
            whitelist_sni_file: d_whitelist_sni_file(),
            debug: false,
            config_load_error: None,
            config_warnings: Vec::new(),
        }
    }
}

const KNOWN_KEYS: &[&str] = &[
    "MAX_CONCURRENT", "IP_VERSION", "PROXY_URL", "CONNECT_TIMEOUT", "READ_TIMEOUT",
    "POOL_TIMEOUT", "STUB_IPS_TIMEOUT", "TCP_BLOCK_MIN_KB", "TCP_BLOCK_MAX_KB",
    "FAT_DEFAULT_SNI", "FAT_CONNECT_TIMEOUT", "FAT_READ_TIMEOUT", "USER_AGENT",
    "WSAECONNRESET", "WSAECONNREFUSED", "WSAETIMEDOUT", "WSAENETUNREACH",
    "WSAEHOSTUNREACH", "WSAECONNABORTED", "DNS_CHECK_TIMEOUT", "DNS_AVAILABILITY_TIMEOUT",
    "DNS_PROBE_CONCURRENCY", "DNS_CHECK_DOMAINS", "DNS_UDP_SERVERS",
    "DNS_AVAILABILITY_DOMAINS", "DNS_AVAILABILITY_SERVERS", "DNS_UDP_CONCURRENCY",
    "DNS_DOH_CONCURRENCY", "DNS_EGRESS_CONCURRENCY", "DNS_ASN_CONCURRENCY",
    "ASN_CACHE_FILE", "FAT_CHUNKS_COUNT", "FAT_CHUNK_SIZE", "FAT_CHUNK_DELAY",
    "FAT_RANDOM_POOL_SIZE", "SNI_BATCH_SIZE", "SNI_TOP_N", "TELEGRAM_MEDIA_URL",
    "TELEGRAM_MEDIA_SIZE_MB", "TELEGRAM_UPLOAD_IP", "TELEGRAM_UPLOAD_PORT",
    "TELEGRAM_UPLOAD_SIZE_MB", "TELEGRAM_STALL_TIMEOUT", "TELEGRAM_TOTAL_TIMEOUT",
    "TELEGRAM_DC_PING_TIMEOUT", "TELEGRAM_DC_PORT", "TELEGRAM_DCS", "PIN_CACHE_MAX",
    "PIN_CACHE_TTL", "CONCURRENCY_PRESETS", "BYPASS_TOOLS", "DNS_KNOWN_RESOLVER_NAMES",
    "DNS_STUB_THRESHOLD", "DEBUG", "CYMRU_DOH_SERVERS", "IP4_LOOKUP_URLS",
    "IP6_LOOKUP_URLS", "IP_LOOKUP_URLS",
];

/// Per-key type validation (mirrors Python VALIDATORS): a mistyped value is
/// dropped so its default survives, and a warning names the key. Without
/// this, one bad scalar fails the whole serde mapping and resets everything.
fn sanitize_mapping(mapping: &mut serde_yaml::Mapping, warnings: &mut Vec<String>) {
    let is_uint = |v: &serde_yaml::Value| v.as_u64().is_some();
    let is_num = |v: &serde_yaml::Value| v.as_u64().is_some() || v.as_f64().is_some();
    // Canonical key order is UPPER_SNAKE (mirrors config.yml).
    let up = |k: &serde_yaml::Value| k.as_str().map(|s| s.to_uppercase());
    let mut drop_keys: Vec<serde_yaml::Value> = Vec::new();
    for (k, v) in mapping.iter_mut() {
        let key = match up(k) {
            Some(s) => s,
            None => continue,
        };
        let ok = match key.as_str() {
            "MAX_CONCURRENT" | "DNS_PROBE_CONCURRENCY" | "DNS_UDP_CONCURRENCY"
            | "DNS_DOH_CONCURRENCY" | "DNS_EGRESS_CONCURRENCY" | "DNS_ASN_CONCURRENCY"
            | "FAT_CHUNKS_COUNT" | "FAT_CHUNK_SIZE" | "FAT_RANDOM_POOL_SIZE"
            | "SNI_BATCH_SIZE" | "SNI_TOP_N" | "TCP_BLOCK_MIN_KB" | "TCP_BLOCK_MAX_KB" => {
                is_uint(v)
            }
            "TELEGRAM_UPLOAD_PORT" | "TELEGRAM_DC_PORT" => {
                v.as_u64().is_some_and(|p| (1..=65535).contains(&p))
            }
            "DNS_STUB_THRESHOLD" => v.as_u64().is_some_and(|t| (1..=50).contains(&t)),
            "CONNECT_TIMEOUT" | "READ_TIMEOUT" | "POOL_TIMEOUT" | "STUB_IPS_TIMEOUT"
            | "DNS_CHECK_TIMEOUT" | "DNS_AVAILABILITY_TIMEOUT" | "FAT_CONNECT_TIMEOUT"
            | "FAT_READ_TIMEOUT" | "FAT_CHUNK_DELAY" | "TELEGRAM_MEDIA_SIZE_MB"
            | "TELEGRAM_UPLOAD_SIZE_MB" | "TELEGRAM_STALL_TIMEOUT" | "TELEGRAM_TOTAL_TIMEOUT"
            | "TELEGRAM_DC_PING_TIMEOUT" => {
                if !is_num(v) || v.as_f64().is_none_or(|f| f <= 0.0) {
                    false
                } else {
                    // Normalize ints (e.g. `CONNECT_TIMEOUT: 15`) to f64 so the
                    // f64 struct field deserializes instead of failing the file.
                    if v.as_u64().is_some() {
                        if let Some(f) = v.as_f64() {
                            *v = serde_yaml::Value::Number(serde_yaml::Number::from(f));
                        }
                    }
                    true
                }
            }
            "IP_VERSION" => matches!(v.as_str(), Some("ipv4") | Some("ipv6")),
            "FAT_DEFAULT_SNI" | "USER_AGENT" | "TELEGRAM_MEDIA_URL" | "TELEGRAM_UPLOAD_IP" => {
                v.as_str().is_some()
            }
            "PROXY_URL" | "ASN_CACHE_FILE" => v.is_null() || v.as_str().is_some(),
            "DEBUG" => v.as_bool().is_some(),
            // String lists: keep string elements (mirrors Python comment
            // stripping at load; a non-string element is ignored, not fatal).
            "DNS_CHECK_DOMAINS" | "DNS_AVAILABILITY_DOMAINS" | "DNS_KNOWN_RESOLVER_NAMES"
            | "CYMRU_DOH_SERVERS" | "IP4_LOOKUP_URLS" | "IP6_LOOKUP_URLS" | "IP_LOOKUP_URLS" => {
                match v {
                    serde_yaml::Value::Sequence(seq) => {
                        seq.retain(|e| e.as_str().is_some());
                        true
                    }
                    _ => false,
                }
            }
            // Pair lists: keep [str, str, ...] rows with ≥2 columns.
            "DNS_UDP_SERVERS" | "TELEGRAM_DCS" => match v {
                serde_yaml::Value::Sequence(rows) => {
                    rows.retain(|r| match r {
                        serde_yaml::Value::Sequence(cols) => {
                            cols.len() >= 2 && cols.iter().all(|c| c.as_str().is_some())
                        }
                        _ => false,
                    });
                    true
                }
                _ => false,
            },
            _ => true,
        };
        if !ok {
            warnings.push(format!("{} has invalid value, using default", key));
            drop_keys.push(k.clone());
        }
    }
    for k in &drop_keys {
        mapping.remove(k);
    }
}

impl AppConfig {
    /// Parses `config.yml` content. Unknown keys produce warnings (mirrors Python).
    pub fn from_yaml_str(content: &str) -> Self {
        let value: serde_yaml::Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                let mut cfg: Self = serde_yaml::from_str("{}").unwrap();
                cfg.config_load_error = Some(format!("config.yml parse error: {}", e));
                return cfg;
            }
        };
        let mut mapping = match value.as_mapping() {
            Some(m) => m.clone(),
            None => {
                let mut cfg: Self = serde_yaml::from_str("{}").unwrap();
                cfg.config_load_error = Some("config.yml root is not a mapping".to_string());
                return cfg;
            }
        };

        let mut warnings = Vec::new();
        for key in mapping.keys() {
            if let Some(k) = key.as_str() {
                let upper = k.to_uppercase();
                if !KNOWN_KEYS.contains(&upper.as_str()) {
                    warnings.push(format!("Unknown config key: {}", k));
                }
            }
        }
        sanitize_mapping(&mut mapping, &mut warnings);
        // IP_LOOKUP_URLS compat (mirrors netinfo.py): v4 lookup falls back to
        // the shared list when IP4_LOOKUP_URLS is absent. v6 keeps its own
        // default, exactly like Python.
        let has_ip4 = mapping
            .keys()
            .any(|k| k.as_str().is_some_and(|s| s.eq_ignore_ascii_case("IP4_LOOKUP_URLS")));
        if !has_ip4 {
            let compat = mapping.iter().find_map(|(k, v)| {
                if k.as_str().is_some_and(|s| s.eq_ignore_ascii_case("IP_LOOKUP_URLS"))
                    && v.is_sequence()
                {
                    Some(v.clone())
                } else {
                    None
                }
            });
            if let Some(urls) = compat {
                mapping.insert(
                    serde_yaml::Value::String("IP4_LOOKUP_URLS".to_string()),
                    urls,
                );
            }
        }

        // Normalize keys to lowercase struct fields
        let mut norm = serde_yaml::Mapping::new();
        for (k, v) in mapping {
            if let Some(ks) = k.as_str() {
                norm.insert(
                    serde_yaml::Value::String(ks.to_lowercase()),
                    v.clone(),
                );
            }
        }
        let mut cfg: Self = serde_yaml::from_value(serde_yaml::Value::Mapping(norm))
            .unwrap_or_else(|_| serde_yaml::from_str("{}").unwrap());
        cfg.config_warnings = warnings;
        cfg.clamp();
        cfg
    }

    fn clamp(&mut self) {
        if self.max_concurrent < 1 {
            self.max_concurrent = 50;
            self.config_warnings.push("MAX_CONCURRENT < 1, reset to 50".to_string());
        }
        if self.ip_version != "ipv4" && self.ip_version != "ipv6" {
            self.ip_version = "ipv4".to_string();
            self.config_warnings.push("IP_VERSION invalid, reset to ipv4".to_string());
        }
        if !(1..=50).contains(&self.dns_stub_threshold) {
            self.dns_stub_threshold = 2;
            self.config_warnings.push("DNS_STUB_THRESHOLD out of range 1..50, reset to 2".to_string());
        }
        if self.telegram_upload_port == 0 {
            self.telegram_upload_port = 443;
            self.config_warnings.push("TELEGRAM_UPLOAD_PORT invalid, reset to 443".to_string());
        }
        if self.telegram_dc_port == 0 {
            self.telegram_dc_port = 443;
            self.config_warnings.push("TELEGRAM_DC_PORT invalid, reset to 443".to_string());
        }
        if self.fat_chunks_count < 1 {
            self.fat_chunks_count = 10;
        }
        if self.fat_chunk_size < 1 {
            self.fat_chunk_size = 4000;
        }
    }

    /// Effective proxy URL (CLI --proxy wins over config file).
    pub fn effective_proxy(&self) -> Option<&str> {
        self.proxy
            .as_deref()
            .or(self.proxy_url.as_deref())
    }

    /// Parsed availability servers, skipping malformed rows.
    pub fn availability_servers(&self) -> Vec<DnsAvailServer> {
        let mut out = Vec::new();
        for row in &self.dns_availability_servers {
            if row.len() < 3 {
                continue;
            }
            let addr = match yaml_str(&row[0]) {
                Some(s) => s,
                None => continue,
            };
            let name = match yaml_str(&row[1]) {
                Some(s) => s,
                None => continue,
            };
            let kind = match yaml_str(&row[2]) {
                Some(s) => s.to_lowercase(),
                None => continue,
            };
            if !["udp", "doh_json", "doh_wire", "dot"].contains(&kind.as_str()) {
                continue;
            }
            let port = if row.len() > 3 {
                yaml_str(&row[3])
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or_else(|| DnsAvailServer::default_port(&kind))
            } else {
                DnsAvailServer::default_port(&kind)
            };
            out.push(DnsAvailServer { addr, name, kind, port });
        }
        out
    }

    /// Parsed bypass tools: (display name, lowercase patterns).
    pub fn bypass_tools(&self) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for row in &self.bypass_tools_raw {
            if row.len() < 2 {
                continue;
            }
            let name = match yaml_str(&row[0]) {
                Some(s) => s,
                None => continue,
            };
            let patterns = match &row[1] {
                serde_yaml::Value::Sequence(seq) => seq
                    .iter()
                    .filter_map(yaml_str)
                    .map(|s| s.to_lowercase())
                    .collect(),
                _ => continue,
            };
            out.push((name, patterns));
        }
        out
    }

    /// Telegram DC list as (ip, label).
    pub fn telegram_dc_list(&self) -> Vec<(String, String)> {
        self.telegram_dcs
            .iter()
            .filter_map(|row| {
                if row.len() >= 2 {
                    Some((row[0].clone(), row[1].clone()))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Shipped lists embedded into the binary (workspace-root config.yml,
/// domains.txt, tcp16.json, whitelist_sni.txt). External files (cwd, then exe
/// dir) win when present; the embedded copies keep the standalone binary
/// fully working from any directory, including routers.
pub const EMBEDDED_CONFIG_YML: &str = include_str!("../../../config.yml");
const EMBEDDED_DOMAINS_TXT: &str = include_str!("../../../domains.txt");
const EMBEDDED_TCP16_JSON: &str = include_str!("../../../tcp16.json");
const EMBEDDED_WHITELIST_SNI_TXT: &str = include_str!("../../../whitelist_sni.txt");

/// Locates config.yml: current dir first, then executable dir (mirrors get_config_path).
pub fn find_config_file() -> Option<PathBuf> {
    let cwd = Path::new("config.yml");
    if cwd.exists() {
        return Some(cwd.to_path_buf());
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("config.yml");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Loads config.yml if present, otherwise the embedded copy (mirrors load_config).
pub fn load_config() -> AppConfig {
    match find_config_file() {
        Some(path) => match fs::read_to_string(&path) {
            Ok(content) => AppConfig::from_yaml_str(&content),
            Err(e) => AppConfig {
                config_load_error: Some(format!("cannot read {}: {}", path.display(), e)),
                ..AppConfig::default()
            },
        },
        // No external file: the lists shipped inside the binary keep it working.
        None => AppConfig::from_yaml_str(EMBEDDED_CONFIG_YML),
    }
}

/// Directory of the running binary (mirrors get_base_dir).
pub fn base_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.to_path_buf();
        }
    }
    PathBuf::from(".")
}

/// Resolves a resource file: external path first (cwd, then exe dir).
pub fn resource_path(name: &str) -> PathBuf {
    let cwd = Path::new(name);
    if cwd.exists() {
        return cwd.to_path_buf();
    }
    let ext = base_dir().join(name);
    if ext.exists() {
        return ext;
    }
    PathBuf::from(name)
}

/// Cleans a raw domain string (mirrors clean_hostname): strips scheme, path,
/// port, brackets; lowercases. Returns None for empty input.
pub fn clean_domain(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s = s[..idx].to_string();
    }
    // IPv6 literal in brackets
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host = s[1..end].to_string();
            return if host.is_empty() { None } else { Some(host) };
        }
        return None;
    }
    // Bare IPv6 literal (multiple colons, no port possible)
    if s.matches(':').count() >= 2 {
        return Some(s);
    }
    // Strip :port
    if let Some(idx) = s.rfind(':') {
        let port_part = &s[idx + 1..];
        if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
            s = s[..idx].to_string();
        }
    }
    s = s.trim_matches('.').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Loads and cleans domain names from a line-separated text file.
pub fn load_domains_from_file(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(clean_domain)
        .collect())
}

/// Loads whitelist SNI entries (mirrors load_whitelist_sni): non-empty,
/// non-comment lines with their 1-based file numbers.
pub fn load_whitelist_sni(path: impl AsRef<Path>) -> Vec<(String, usize)> {
    let content = fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    let mut num = 0usize;
    for line in content.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        num += 1;
        out.push((s.to_string(), num));
    }
    out
}

/// Domains shipped inside the binary (fallback when domains.txt is absent).
pub fn embedded_domains() -> Vec<String> {
    EMBEDDED_DOMAINS_TXT
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(clean_domain)
        .collect()
}

/// Whitelist SNI shipped inside the binary.
pub fn embedded_whitelist_sni() -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut num = 0usize;
    for line in EMBEDDED_WHITELIST_SNI_TXT.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        num += 1;
        out.push((s.to_string(), num));
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tcp16Target {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub asn: String,
    #[serde(default)]
    pub provider: String,
    pub ip: String,
    #[serde(default = "default_tcp16_port")]
    pub port: u16,
    #[serde(default)]
    pub sni: Option<String>,
}

fn default_tcp16_port() -> u16 {
    443
}

/// Loads TCP16 targets from a JSON file.
pub fn load_tcp16_targets_from_file(path: impl AsRef<Path>) -> io::Result<Vec<Tcp16Target>> {
    let content = fs::read_to_string(path)?;
    let targets: Vec<Tcp16Target> = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(targets)
}

/// Default fallback list of TCP16 targets if file is absent.
pub fn default_tcp16_targets() -> Vec<Tcp16Target> {
    vec![
        Tcp16Target { id: "HE-01".into(), asn: "24940".into(), provider: "Hetzner".into(), ip: "91.98.156.82".into(), port: 443, sni: None },
        Tcp16Target { id: "CF-01".into(), asn: "13335".into(), provider: "Cloudflare".into(), ip: "172.67.70.222".into(), port: 443, sni: None },
        Tcp16Target { id: "AK-01".into(), asn: "20940".into(), provider: "Akamai".into(), ip: "23.222.76.4".into(), port: 443, sni: None },
        Tcp16Target { id: "AWS-02".into(), asn: "16509".into(), provider: "AWS".into(), ip: "3.165.188.250".into(), port: 443, sni: None },
    ]
}

/// TCP16 targets shipped inside the binary.
pub fn embedded_tcp16_targets() -> Vec<Tcp16Target> {
    serde_json::from_str(EMBEDDED_TCP16_JSON).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_domain() {
        assert_eq!(clean_domain("https://Example.COM:443/path?q=1"), Some("example.com".to_string()));
        assert_eq!(clean_domain("  vk.ru  "), Some("vk.ru".to_string()));
        assert_eq!(clean_domain("[2001:db8::1]:8080"), Some("2001:db8::1".to_string()));
        assert_eq!(clean_domain("2001:db8::1"), Some("2001:db8::1".to_string()));
        assert_eq!(clean_domain(""), None);
    }

    #[test]
    fn test_config_defaults() {
        // Mirrors Python `test_default_values_present` (+ threshold default).
        let cfg = AppConfig::default();
        assert_eq!(cfg.max_concurrent, 50);
        assert_eq!(cfg.ip_version, "ipv4");
        assert!(cfg.connect_timeout > 0.0);
        assert!(cfg.dns_probe_concurrency > 0);
        assert_eq!(cfg.dns_stub_threshold, 2);
        assert_eq!(cfg.fat_chunks_count, 10);
        assert_eq!(cfg.telegram_dcs.len(), 5);
        assert!(!cfg.bypass_tools().is_empty());
    }

    #[test]
    fn test_config_from_yaml() {
        let cfg = AppConfig::from_yaml_str("MAX_CONCURRENT: 20\nIP_VERSION: ipv6\nUNKNOWN_KEY_X: 1\n");
        assert_eq!(cfg.max_concurrent, 20);
        assert_eq!(cfg.ip_version, "ipv6");
        assert_eq!(cfg.config_warnings.len(), 1);
    }

    #[test]
    fn test_availability_servers_parse() {
        let yaml = "DNS_AVAILABILITY_SERVERS:\n  - [\"8.8.8.8\", \"Google\", \"udp\"]\n  - [\"dns.google\", \"Google\", \"dot\", 8853]\n";
        let cfg = AppConfig::from_yaml_str(yaml);
        let servers = cfg.availability_servers();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].port, 53);
        assert_eq!(servers[1].port, 8853);
    }

    /// Mirrors Python `test_type_and_range_validation_retains_default`:
    /// each bad key keeps its default and is named in warnings.
    #[test]
    fn test_invalid_values_retain_default() {
        let yaml = "MAX_CONCURRENT: \"one hundred\"\nIP_VERSION: \"ipv5\"\nCONNECT_TIMEOUT: -5.0\nUNKNOWN_SECRET_KEY: 12345\n";
        let cfg = AppConfig::from_yaml_str(yaml);
        assert_eq!(cfg.max_concurrent, 50);
        assert_eq!(cfg.ip_version, "ipv4");
        assert_eq!(cfg.connect_timeout, 8.0);
        let text = cfg.config_warnings.join(" ");
        assert!(text.contains("MAX_CONCURRENT"), "{text}");
        assert!(text.contains("IP_VERSION"), "{text}");
        assert!(text.contains("CONNECT_TIMEOUT"), "{text}");
        assert!(text.contains("UNKNOWN_SECRET_KEY"), "{text}");
    }

    /// Mirrors Python `test_valid_custom_config_loads_successfully`.
    #[test]
    fn test_valid_custom_config() {
        let yaml = "MAX_CONCURRENT: 25\nIP_VERSION: \"ipv6\"\nCONNECT_TIMEOUT: 15.0\nDNS_STUB_THRESHOLD: 3\n";
        let cfg = AppConfig::from_yaml_str(yaml);
        assert_eq!(cfg.max_concurrent, 25);
        assert_eq!(cfg.ip_version, "ipv6");
        assert_eq!(cfg.connect_timeout, 15.0);
        assert_eq!(cfg.dns_stub_threshold, 3);
        assert!(cfg.config_warnings.is_empty(), "{:?}", cfg.config_warnings);
    }

    /// `IP_LOOKUP_URLS` compat (mirrors netinfo.py): v4 falls back to the
    /// shared list, v6 keeps its own default.
    #[test]
    fn test_ip_lookup_urls_compat() {
        let yaml = "IP_LOOKUP_URLS:\n  - \"https://example.com/v4\"\n";
        let cfg = AppConfig::from_yaml_str(yaml);
        assert_eq!(cfg.ip4_lookup_urls, vec!["https://example.com/v4".to_string()]);
        assert_eq!(cfg.ip6_lookup_urls, d_ip6_lookup_urls());
        // Explicit IP4 wins over compat.
        let yaml = "IP_LOOKUP_URLS:\n  - \"https://example.com/v4\"\nIP4_LOOKUP_URLS:\n  - \"https://example.com/other\"\n";
        let cfg = AppConfig::from_yaml_str(yaml);
        assert_eq!(cfg.ip4_lookup_urls, vec!["https://example.com/other".to_string()]);
    }

    /// All test lists are 100% identical to the shipped config.yml shared
    /// with the Python implementation: any drift fails here.
    #[test]
    fn test_lists_match_shipped_config_yml() {
        let cfg = AppConfig::from_yaml_str(include_str!("../../../config.yml"));
        assert!(cfg.config_load_error.is_none(), "{:?}", cfg.config_load_error);
        assert_eq!(
            cfg.dns_check_domains,
            vec!["rutor.info", "flibusta.is", "clubtone.do.am", "rezka.ag", "shikimori.one"]
        );
        assert_eq!(cfg.dns_udp_servers.len(), 13);
        assert_eq!(cfg.dns_udp_servers[0], vec!["8.8.8.8", "Google"]);
        assert_eq!(cfg.dns_availability_domains, vec!["vk.ru", "gosuslugi.ru"]);
        let servers = cfg.availability_servers();
        assert_eq!(servers.iter().filter(|s| s.kind == "udp").count(), 37);
        assert_eq!(servers.iter().filter(|s| s.kind == "doh_wire").count(), 36);
        assert_eq!(servers.iter().filter(|s| s.kind == "dot").count(), 33);
        assert_eq!(servers.len(), 106);
        assert_eq!(servers[0].addr, "94.140.14.14");
        assert_eq!(servers.last().map(|s| s.kind.as_str()), Some("dot"));
        assert_eq!(cfg.telegram_dc_list().len(), 5);
        assert_eq!(cfg.telegram_dc_list()[0], ("149.154.175.53".to_string(), "DC1".to_string()));
        let tools = cfg.bypass_tools();
        assert_eq!(tools.len(), 24);
        assert_eq!(tools[0].0, "zapret");
        assert_eq!(cfg.ip4_lookup_urls.len(), 3);
        assert_eq!(cfg.concurrency_presets, vec![1, 5, 20, 50, 100]);
        assert_eq!(cfg.cymru_doh_servers.len(), 5);
        assert_eq!(cfg.ip6_lookup_urls.len(), 4);
        assert_eq!(cfg.dns_known_resolver_names.len(), 27);
        assert!(cfg.dns_known_resolver_names.contains(&"google".to_string()));
        assert!(cfg.dns_known_resolver_names.contains(&"yandex".to_string()));
    }

    /// No-file fallbacks carry the same lists (embedded use without config.yml).
    #[test]
    fn test_default_lists_match_shipped_yml() {
        let from_yml = AppConfig::from_yaml_str(include_str!("../../../config.yml"));
        let def = AppConfig::default();
        assert_eq!(def.dns_check_domains, from_yml.dns_check_domains);
        assert_eq!(def.dns_udp_servers, from_yml.dns_udp_servers);
        assert_eq!(def.dns_availability_domains, from_yml.dns_availability_domains);
        assert_eq!(def.telegram_dcs, from_yml.telegram_dcs);
        assert_eq!(def.bypass_tools(), from_yml.bypass_tools());
        assert_eq!(def.cymru_doh_servers, from_yml.cymru_doh_servers);
        assert_eq!(def.ip4_lookup_urls, from_yml.ip4_lookup_urls);
        assert_eq!(def.ip6_lookup_urls, from_yml.ip6_lookup_urls);
        assert_eq!(def.dns_known_resolver_names, from_yml.dns_known_resolver_names);
        assert_eq!(def.concurrency_presets, from_yml.concurrency_presets);
    }

    /// Embedded fallbacks parse to the same lists as the shipped files.
    #[test]
    fn test_embedded_lists_match_files() {
        let domains = embedded_domains();
        assert_eq!(domains.len(), 36);
        assert!(domains.contains(&"vk.ru".to_string()));
        assert!(domains.contains(&"www.instagram.com".to_string()));
        let file_targets: Vec<Tcp16Target> =
            serde_json::from_str(include_str!("../../../tcp16.json")).unwrap();
        assert_eq!(embedded_tcp16_targets(), file_targets);
        assert!(!embedded_tcp16_targets().is_empty());
        assert!(!embedded_whitelist_sni().is_empty());
        let cfg = AppConfig::from_yaml_str(EMBEDDED_CONFIG_YML);
        assert_eq!(cfg.availability_servers().len(), 106);
    }
}
