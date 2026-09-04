use std::env;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Ru,
    Fa,
    Zh,
    Es,
    Ar,
}

impl Language {
    pub const ALL: [Self; 6] = [
        Self::En,
        Self::Ru,
        Self::Fa,
        Self::Zh,
        Self::Es,
        Self::Ar,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Fa => "فارسی\u{200E}",
            Self::Zh => "中文",
            Self::Es => "Español",
            Self::Ar => "العربية\u{200E}",
        }
    }
    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "en" | "en_us" | "en_gb" | "english" => Some(Self::En),
            "ru" | "ru_ru" | "russian" => Some(Self::Ru),
            "fa" | "fa_ir" | "farsi" | "persian" => Some(Self::Fa),
            "zh" | "zh_cn" | "zh_hans" | "chinese" => Some(Self::Zh),
            "es" | "es_es" | "es_cu" | "spanish" => Some(Self::Es),
            "ar" | "ar_eg" | "ar_ae" | "arabic" => Some(Self::Ar),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Fa => "fa",
            Self::Zh => "zh",
            Self::Es => "es",
            Self::Ar => "ar",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Fa => "فارسی",
            Self::Zh => "简体中文",
            Self::Es => "Español",
            Self::Ar => "العربية",
        }
    }

    pub fn is_rtl(&self) -> bool {
        matches!(self, Self::Fa | Self::Ar)
    }

    /// Autodetects system language from environment variables (LANG, LC_ALL, LC_MESSAGES).
    pub fn autodetect() -> Self {
        for var in &["LC_ALL", "LANG", "LC_MESSAGES"] {
            if let Ok(val) = env::var(var) {
                let code = val.split('.').next().unwrap_or(&val);
                let lang_prefix = code.split('_').next().unwrap_or(code);
                if let Some(lang) = Self::from_code(lang_prefix) {
                    return lang;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(lang) = detect_windows_language() {
                return lang;
            }
        }
        Self::En
    }
}

/// Shapes Arabic and Persian text into cursive presentation glyphs for terminal display.
/// Preserves natural character order (no backwards flipping) and preserves ANSI escape sequences.
/// For LTR languages (English, Russian, Chinese, Spanish), returns the text unchanged.
pub fn format_bidi(text: &str, lang: Language) -> String {
    if !lang.is_rtl() {
        return text.to_string();
    }
    format_bidi_str(text)
}

/// Shapes Arabic script characters into connected cursive ligatures/presentation forms
/// without reversing character order.
pub fn reshape_arabic(text: &str) -> String {
    format_bidi_segment(text)
}

fn format_bidi_segment(text: &str) -> String {
    if !text.chars().any(|c| matches!(c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')) {
        return text.to_string();
    }
    arabic_reshaper::arabic_reshape(text)
}

/// Shapes Arabic script characters into connected ligatures/presentation forms
/// and reorders lines for terminal display. Preserves ANSI escape sequences untouched.
pub fn format_bidi_str(text: &str) -> String {
    if !text.chars().any(|c| matches!(c, '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' | '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')) {
        return text.to_string();
    }

    if text.contains('\x1b') {
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        let bytes = text.as_bytes();
        let len = bytes.len();
        while i < len {
            if bytes[i] == 0x1b && i + 1 < len && bytes[i + 1] == b'[' {
                let start = i;
                i += 2;
                while i < len && !bytes[i].is_ascii_alphabetic() {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
                out.push_str(&text[start..i]);
            } else {
                let start = i;
                while i < len && !(bytes[i] == 0x1b && i + 1 < len && bytes[i + 1] == b'[') {
                    i += 1;
                }
                out.push_str(&format_bidi_segment(&text[start..i]));
            }
        }
        return out;
    }

    format_bidi_segment(text)
}

#[cfg(target_os = "windows")]
fn detect_windows_language() -> Option<Language> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let intl = hkcu.open_subkey("Control Panel\\International").ok()?;
    let locale_name: String = intl.get_value("LocaleName").ok()?;
    let prefix = locale_name.split('-').next().unwrap_or(&locale_name);
    Language::from_code(prefix)
}

pub struct Messages {
    pub banner_subtitle: &'static str,
    pub netinfo_title: &'static str,
    pub dns_title: &'static str,
    pub domain_title: &'static str,
    pub tcp16_title: &'static str,
    pub telegram_title: &'static str,
    pub summary_title: &'static str,
    pub resolver: &'static str,
    pub status: &'static str,
    pub ip_count: &'static str,
    pub latency: &'static str,
    pub available: &'static str,
    pub blocked: &'static str,
    pub domain: &'static str,
    pub stage: &'static str,
    pub bytes: &'static str,
    pub duration: &'static str,
    pub detail: &'static str,
    pub target: &'static str,
    pub provider: &'static str,
    pub region: &'static str,
    pub speed: &'static str,
    pub bypass_tools: &'static str,
    pub gateway: &'static str,
    pub syn_drop_desc: &'static str,
    pub tcp_rst_desc: &'static str,
    pub tls_rst_desc: &'static str,
    pub tls_drop_desc: &'static str,
    pub tls_alert_desc: &'static str,
    pub http_blocked_desc: &'static str,
    pub tcp16_drop_desc: &'static str,
    pub unreachable_desc: &'static str,
    pub menu_title: &'static str,
    pub menu_language: &'static str,
    pub menu_ip_version: &'static str,
    pub menu_concurrency: &'static str,
    pub menu_hw_row: &'static str,
    pub menu_hw_change: &'static str,
    pub menu_hw_tests: &'static str,
    pub menu_hw_start: &'static str,
    pub menu_hw_quit: &'static str,
    pub menu_line_prompt: &'static str,
    pub menu_invalid_line: &'static str,
    pub menu_need_one: &'static str,
    pub menu_test_netinfo: &'static str,
    pub menu_test_dns: &'static str,
    pub menu_test_domains: &'static str,
    pub menu_test_tcp: &'static str,
    pub menu_test_sni: &'static str,
    pub menu_test_telegram: &'static str,
    pub menu_test_legend: &'static str,
    pub lang: Language,
    pub replies_label: &'static str,
    pub blocked_short: &'static str,
    pub mixed_short: &'static str,
    pub legend_title: &'static str,

    // Banner & Version
    pub latest_version: &'static str,
    pub author: &'static str,
    pub chat: &'static str,
    pub checking_updates: &'static str,

    // NetInfo panel
    pub os: &'static str,
    pub system_dns: &'static str,
    pub active_interface: &'static str,
    pub inactive_dns: &'static str,
    pub router_resolver: &'static str,
    pub upstream_vpn: &'static str,
    pub wsl_proxy: &'static str,
    pub wsl_network: &'static str,
    pub local_bypass: &'static str,
    pub not_detected: &'static str,
    pub unavailable: &'static str,

    // DNS Endpoints & Availability
    pub dns_check_title: &'static str,
    pub doh_endpoints: &'static str,
    pub dot_endpoints: &'static str,
    pub udp_endpoints: &'static str,
    pub doh_min: &'static str,
    pub dot_min: &'static str,
    pub udp_min: &'static str,
    pub real_udp_resolver: &'static str,
    pub spoofing: &'static str,
    pub timeout_label: &'static str,
    pub egress_na: &'static str,
    pub partial_dns_warn: &'static str,
    pub dns_fakeip_warn: &'static str,
    pub dns_intercept_warn: &'static str,
    pub dns_stub_ip_label: &'static str,
    pub doh_recommendation: &'static str,
    pub non_socks_proxy_warn: &'static str,
    pub blocked_domains_label: &'static str,
    pub unblocked_domains_label: &'static str,
    pub dns_independent_warn: &'static str,

    // Domain Table & DNS Notes
    pub http: &'static str,
    pub tls12: &'static str,
    pub tls13: &'static str,
    pub dns_info_title: &'static str,
    pub traffic_fakeip: &'static str,
    pub dns_isp_stub: &'static str,
    pub dns_local_ip: &'static str,
    pub dns_fail_detected: &'static str,
    pub doh_flush_guide: &'static str,

    // TCP 16KB & Whitelist
    pub tcp16_check_title: &'static str,
    pub tcp_mixed_warn: &'static str,
    pub no_port_443_targets: &'static str,
    pub no_as_blocked: &'static str,
    pub ban_after_label: &'static str,
    pub ban_rate_limit: &'static str,
    pub sni_not_found: &'static str,
    pub whitelist_found_summary: &'static str,
    pub whitelist_none_summary: &'static str,
    pub whitelist_skipped: &'static str,

    // Telegram
    pub telegram_check_title: &'static str,
    pub dc_col: &'static str,
    pub ip_col: &'static str,
    pub ping_col: &'static str,
    pub download_label: &'static str,
    pub upload_label: &'static str,
    pub peak_label: &'static str,
    pub avg_label: &'static str,
    pub stall_after: &'static str,
    pub ms_unit: &'static str,

    // Summary
    pub summary_dns_avail: &'static str,
    pub summary_resolver_hijack: &'static str,
    pub summary_all: &'static str,
    pub summary_fakeip_resp: &'static str,
    pub summary_ans_hijack: &'static str,
    pub summary_domains: &'static str,
    pub summary_tg_download: &'static str,
    pub summary_tg_upload: &'static str,
    pub summary_tg_datacenters: &'static str,

    // Controls & Pipeline
    pub menu_control_repeat: &'static str,
    pub menu_control_menu: &'static str,
    pub menu_control_export: &'static str,
    pub menu_control_exit: &'static str,
    pub report_saved: &'static str,
    pub report_save_fail: &'static str,
    pub invalid_tests_flag: &'static str,
    pub invalid_concurrency_flag: &'static str,
    pub tui_unavailable: &'static str,
    pub ipv6_not_configured: &'static str,
    pub ipv6_switch_hint: &'static str,
    pub fetching_net_info: &'static str,
    pub net_info_unavailable: &'static str,
    pub domains_check_header: &'static str,
    pub targets_label: &'static str,
    pub phase_dns: &'static str,
    pub phase_tls13: &'static str,
    pub phase_tls12: &'static str,
    pub phase_http: &'static str,
    pub checking_status: &'static str,
    pub phase_sni_base: &'static str,
    pub phase_sni_parallel: &'static str,
}

impl Messages {
    /// Checkbox label for test digit '0'..='6' in the interactive menu
    /// (mirrors Python `_MENU_OPTIONS`).
    pub fn menu_test_label(&self, digit: char) -> &'static str {
        match digit {
            '0' => self.menu_test_netinfo,
            '1' => self.menu_test_dns,
            '2' => self.menu_test_domains,
            '3' => self.menu_test_tcp,
            '4' => self.menu_test_sni,
            '5' => self.menu_test_telegram,
            '6' => self.menu_test_legend,
            _ => "",
        }
    }
}

pub fn get_messages(lang: Language) -> Messages {
    match lang {
        Language::En => Messages {
            banner_subtitle: "Rust Native DPI & Censorship Diagnostic Engine",
            netinfo_title: "Network & System Information",
            dns_title: "DNS Resolver Availability:",
            domain_title: "TLS / SNI Domain Inspection Results:",
            tcp16_title: "TCP 16–20 KB Window Throttling Results:",
            telegram_title: "Telegram Data Centers Availability:",
            summary_title: "Summary",
            resolver: "Resolver",
            status: "Status",
            ip_count: "IP Count",
            latency: "Latency",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Domain",
            stage: "Stage",
            bytes: "Bytes (Tx/Rx)",
            duration: "Duration",
            detail: "Detail",
            target: "Target",
            provider: "Provider",
            region: "Region",
            speed: "Speed",
            bypass_tools: "DPI Bypass Tools",
            gateway: "Default Gateway",
            syn_drop_desc: "SYN DROP (Middlebox dropped TCP SYN packet)",
            tcp_rst_desc: "TCP RST (Connection reset by DPI during connect)",
            tls_rst_desc: "TLS RST (Reset after ClientHello / SNI block)",
            tls_drop_desc: "TLS DROP (Connection dropped during TLS handshake)",
            tls_alert_desc: "TLS ALERT (Certificate error or fatal TLS alert)",
            http_blocked_desc: "HTTP BLOCK (ISP blockpage redirect detected)",
            tcp16_drop_desc: "TCP16 DROP (Window throttled or connection dropped)",
            unreachable_desc: "UNREACHABLE (Network route unreachable)",
            menu_title: "Parameters & test selection",
            menu_language: "Language",
            menu_ip_version: "IP version",
            menu_concurrency: "Concurrency",
            menu_hw_row: "row",
            menu_hw_change: "change",
            menu_hw_tests: "tests",
            menu_hw_start: "start",
            menu_hw_quit: "quit",
            menu_line_prompt: "Enter selection [123]: ",
            menu_invalid_line: "Invalid input, running tests 1, 2, 3.",
            menu_need_one: "Select at least one test",
            menu_test_netinfo: "Network & system information",
            menu_test_dns: "DNS server availability check",
            menu_test_domains: "Domain availability check",
            menu_test_tcp: "TCP 16–20 KB blocking check",
            menu_test_sni: "Whitelist SNI discovery for ASN",
            menu_test_telegram: "Telegram check (throttling/blocking)",
            menu_test_legend: "Status legend (help)",
            lang: Language::En,
            replies_label: "replies",
            blocked_short: "blocked",
            mixed_short: "mixed",
            legend_title: "\nStatus legend:\n",

            latest_version: "✓ Latest version",
            author: "Author:",
            chat: "Chat:",
            checking_updates: "Checking for updates...",
            os: "OS:",
            system_dns: "System DNS:",
            active_interface: "Active interface:",
            inactive_dns: "Inactive DNS:",
            router_resolver: "Router resolver",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "WSL proxy",
            wsl_network: "WSL network:",
            local_bypass: "Local DPI bypass on device:",
            not_detected: "not detected",
            unavailable: "unavailable",

            dns_check_title: "DNS Server Availability Check",
            doh_endpoints: "DoH endpoints",
            dot_endpoints: "DoT endpoints",
            udp_endpoints: "UDP endpoints",
            doh_min: "DoH min",
            dot_min: "DoT min",
            udp_min: "UDP min",
            real_udp_resolver: "Real UDP resolver",
            spoofing: "Spoofing",
            timeout_label: "timeout",
            egress_na: "egress N/A",
            partial_dns_warn: "Partially available DNS servers (packet loss):",
            dns_fakeip_warn: "[!] DNS responses contain FakeIP\nDisable proxy/FakeIP during check for accurate assessment.",
            dns_intercept_warn: "[!] Your ISP intercepts DNS queries\nISP replaces UDP DNS responses with stubs or fake NXDOMAIN/EMPTY/TIMEOUT",
            dns_stub_ip_label: "ISP blockpage IP: {}.",
            doh_recommendation: "Recommendation: Configure DoH on your device/router if not already done.",
            non_socks_proxy_warn: "Proxy is not SOCKS5 — UDP probes bypass proxy: UDP relay is not possible via HTTP proxy.\n",
            blocked_domains_label: "Blocked domains for check:",
            unblocked_domains_label: "Unblocked domains for check:",
            dns_independent_warn: "WARNING: This is an independent check and does not use your configured DNS!\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] DNS RESOLUTION INFO:",
            traffic_fakeip: "Traffic intercepted by Fake-IP: for {} domains",
            dns_isp_stub: "DNS returned ISP blockpage IP ({}): for {} domains",
            dns_local_ip: "DNS returned local IPs (AdGuard/hosts?): ({}): for {} domains",
            dns_fail_detected: "DNS FAIL detected for {} sites",
            doh_flush_guide: "Recommendation: Configure DoH on your device and router\n\nAfter configuring, flush DNS cache:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "TCP 16–20 KB Block Check",
            tcp_mixed_warn: "Mixed results indicate ISP DPI load balancing",
            no_port_443_targets: "No port 443 targets for whitelist SNI test.\n",
            no_as_blocked: "No AS blocked — SNI discovery not needed.\n",
            ban_after_label: "  ⚠ ban after",
            ban_rate_limit: "ban/rate-limit",
            sni_not_found: "× SNI not found (all blocked)",
            whitelist_found_summary: "Found white SNI: in {} of {} blocked AS",
            whitelist_none_summary: "No white SNI found for any of {} blocked AS",
            whitelist_skipped: "File whitelist_sni.txt empty or not found — test 4 skipped.\n",

            telegram_check_title: "Telegram Availability Check",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Ping",
            download_label: "Download",
            upload_label: "Upload  ",
            peak_label: "peak",
            avg_label: "avg",
            stall_after: ", stall after {}s",
            ms_unit: "ms",

            summary_dns_avail: "DNS availability",
            summary_resolver_hijack: "Resolver hijack",
            summary_all: "All",
            summary_fakeip_resp: "FakeIP responses",
            summary_ans_hijack: "Answer hijack",
            summary_domains: "Domains",
            summary_tg_download: "TG Download",
            summary_tg_upload: "TG Upload",
            summary_tg_datacenters: "TG Datacenters",

            menu_control_repeat: "Repeat",
            menu_control_menu: "Menu",
            menu_control_export: "Export",
            menu_control_exit: "Exit",
            report_saved: "✓ Report saved to {}",
            report_save_fail: "Failed to save file: {}",
            invalid_tests_flag: "Invalid value for --tests: '{}'. Only digits 0-6 are allowed.",
            invalid_concurrency_flag: "The --concurrency parameter must be an integer >= 1.",
            tui_unavailable: "TUI is not available in this terminal. Run with parameters, e.g.: dpi-detector -t 1,2,3 --batch (see dpi-detector --help).",
            ipv6_not_configured: "Error: IPv6 mode selected, but IPv6 is not configured on the system.",
            ipv6_switch_hint: "Switch family to IPv4: IP_VERSION: ipv4 in config.yml or left/right arrow in menu.",
            fetching_net_info: "Fetching network info...",
            net_info_unavailable: "Network information unavailable.\n",
            domains_check_header: "Domain Availability Check",
            targets_label: "Targets",
            phase_dns: "Phase 0/3: DNS resolve...",
            phase_tls13: "Phase 1/3: TLS 1.3...",
            phase_tls12: "Phase 2/3: TLS 1.2...",
            phase_http: "Phase 3/3: HTTP...",
            checking_status: "Checking...",
            phase_sni_base: "Phase 1/2: Base check...",
            phase_sni_parallel: "Phase 2/2: Parallel SNI discovery for {} AS (batch {}, top-{})...",
        },
        Language::Ru => Messages {
            banner_subtitle: "Детектор блокировок DPI и цензуры (Rust Native)",
            netinfo_title: "Информация о сети и системе",
            dns_title: "Доступность DNS-резолверов:",
            domain_title: "Результаты проверки доменов (TLS / SNI):",
            tcp16_title: "Результаты проверки TCP 16–20 KB блокировки:",
            telegram_title: "Доступность датацентров Telegram:",
            summary_title: "Итог",
            resolver: "Резолвер",
            status: "Статус",
            ip_count: "Кол-во IP",
            latency: "Задержка",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Домен",
            stage: "Стадия",
            bytes: "Байты (Tx/Rx)",
            duration: "Время",
            detail: "Детали",
            target: "Цель",
            provider: "Провайдер",
            region: "Регион",
            speed: "Скорость",
            bypass_tools: "Обходы DPI",
            gateway: "Основной шлюз",
            syn_drop_desc: "SYN DROP (ТСПУ дропнул пакет TCP SYN)",
            tcp_rst_desc: "TCP RST (ТСПУ сбросил TCP-соединение)",
            tls_rst_desc: "TLS RST (ТСПУ разорвал TLS после ClientHello/SNI)",
            tls_drop_desc: "TLS DROP (ТСПУ дропнул пакеты во время TLS handshake)",
            tls_alert_desc: "TLS ALERT (Ошибка сертификата или фатальный алерт)",
            http_blocked_desc: "HTTP BLOCK (Обнаружен редирект на заглушку провайдера)",
            tcp16_drop_desc: "TCP16 DROP (Сброс соединения при передаче большого окна)",
            unreachable_desc: "UNREACHABLE (Сеть или хост недоступны)",
            menu_title: "Параметры и выбор тестов",
            menu_language: "Language",
            menu_ip_version: "IP-версия",
            menu_concurrency: "Параллельность",
            menu_hw_row: "строка",
            menu_hw_change: "изменить",
            menu_hw_tests: "тесты",
            menu_hw_start: "старт",
            menu_hw_quit: "выход",
            menu_line_prompt: "Введите выбор [123]: ",
            menu_invalid_line: "Неверный ввод, запускаем тесты 1, 2, 3.",
            menu_need_one: "Выберите хотя бы один тест",
            menu_test_netinfo: "Информация о сети и системе",
            menu_test_dns: "Проверка доступности DNS-серверов",
            menu_test_domains: "Проверка доступности доменов",
            menu_test_tcp: "Проверка TCP 16–20 KB блокировки",
            menu_test_sni: "Поиск белых SNI для ASN",
            menu_test_telegram: "Проверка Telegram (замедление/блокировка)",
            menu_test_legend: "Легенда статусов (справка)",
            lang: Language::Ru,
            replies_label: "ответов",
            blocked_short: "блок.",
            mixed_short: "смеш.",
            legend_title: "\nЛегенда статусов:\n",

            latest_version: "✓ Актуальная версия",
            author: "Автор:",
            chat: "Чат:",
            checking_updates: "Проверка обновлений...",
            os: "ОС:",
            system_dns: "Системный DNS:",
            active_interface: "Активный интерфейс:",
            inactive_dns: "Неактивные DNS:",
            router_resolver: "Резолвер роутера",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "прокси WSL",
            wsl_network: "WSL-сеть:",
            local_bypass: "Локальный обход DPI на устройстве:",
            not_detected: "не обнаружен",
            unavailable: "недоступен",

            dns_check_title: "Проверка доступности DNS-серверов",
            doh_endpoints: "DoH эндпоинты",
            dot_endpoints: "DoT эндпоинты",
            udp_endpoints: "UDP эндпоинты",
            doh_min: "DoH мин",
            dot_min: "DoT мин",
            udp_min: "UDP мин",
            real_udp_resolver: "Реальный UDP резолвер",
            spoofing: "Подмена",
            timeout_label: "таймаут",
            egress_na: "выход н/д",
            partial_dns_warn: "Частично доступные DNS-серверы (потери запросов):",
            dns_fakeip_warn: "[!] DNS-ответы содержат FakeIP\nДля честной оценки DNS отключите прокси/FakeIP на время проверки.",
            dns_intercept_warn: "[!] Ваш интернет-провайдер перехватывает DNS-запросы\nПровайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY/TIMEOUT",
            dns_stub_ip_label: "IP адрес заглушки провайдера - {}.",
            doh_recommendation: "Рекомендация: настройте DoH на устройстве/роутере, если еще не сделали этого.",
            non_socks_proxy_warn: "Прокси не SOCKS5 — UDP-пробы идут напрямую: через HTTP-прокси UDP-релей невозможен.\n",
            blocked_domains_label: "Заблокированные домены для проверки:",
            unblocked_domains_label: "Незаблокированные домены для проверки:",
            dns_independent_warn: "ВНИМАНИЕ: Это независимая проверка и она не использует ваши настроенные DNS!\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] ИНФОРМАЦИЯ О DNS РЕЗОЛВЕ:",
            traffic_fakeip: "Трафик перехватывается Fake-IP: у {} доменов",
            dns_isp_stub: "DNS вернул IP заглушки провайдера ({}): у {} доменов",
            dns_local_ip: "DNS вернул локальные IP (работает AdGuard/hosts?): ({}): у {} доменов",
            dns_fail_detected: "У {} сайтов обнаружен DNS FAIL",
            doh_flush_guide: "Рекомендация: Настройте DoH на вашем устройстве и роутере\n\nПосле настройки сбросьте кеш DNS:\nWindows: ipconfig /flushdns\nMacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "Проверка TCP 16-20KB блокировки",
            tcp_mixed_warn: "Смешанные результаты указывают на балансировку DPI у провайдера",
            no_port_443_targets: "Нет целей с портом 443 для теста белых SNI.\n",
            no_as_blocked: "Ни одна AS не заблокирована — перебор SNI не нужен.\n",
            ban_after_label: "  ⚠ бан после",
            ban_rate_limit: "бан/рейт-лимит",
            sni_not_found: "× SNI не найден (все заблокированы)",
            whitelist_found_summary: "Найдено белых SNI: у {} из {} заблокированных AS",
            whitelist_none_summary: "Белые SNI не найдены ни для одной из {} заблокированных AS",
            whitelist_skipped: "Файл whitelist_sni.txt пуст или не найден — тест 4 пропущен.\n",

            telegram_check_title: "Проверка доступности Telegram",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Пинг",
            download_label: "Скачивание",
            upload_label: "Загрузка  ",
            peak_label: "пик",
            avg_label: "ср.",
            stall_after: ", обрыв после {}с",
            ms_unit: "мс",

            summary_dns_avail: "DNS доступность",
            summary_resolver_hijack: "Подмена резолвера",
            summary_all: "Все",
            summary_fakeip_resp: "FakeIP ответов",
            summary_ans_hijack: "Подмена ответов",
            summary_domains: "Домены",
            summary_tg_download: "TG Скачивание",
            summary_tg_upload: "TG Загрузка",
            summary_tg_datacenters: "TG Датацентры",

            menu_control_repeat: "Повторить",
            menu_control_menu: "Меню",
            menu_control_export: "Экспорт",
            menu_control_exit: "Выход",
            report_saved: "✓ Отчёт сохранён в {}",
            report_save_fail: "Не удалось сохранить файл: {}",
            invalid_tests_flag: "Недопустимое значение --tests: '{}'. Допустимы только цифры 0-6.",
            invalid_concurrency_flag: "Параметр --concurrency должен быть целым числом >= 1.",
            tui_unavailable: "TUI недоступно в этом терминале. Запустите с параметрами, например: dpi-detector -t 1,2,3 --batch (см. dpi-detector --help).",
            ipv6_not_configured: "Ошибка: выбран режим IPv6, но IPv6 не настроен в системе.",
            ipv6_switch_hint: "Переключите семейство на IPv4: IP_VERSION: ipv4 в config.yml или стрелки ← → в меню.",
            fetching_net_info: "Получение сетевых данных...",
            net_info_unavailable: "Информация о сети недоступна.\n",
            domains_check_header: "Проверка доступности доменов",
            targets_label: "Целей",
            phase_dns: "Фаза 0/3: DNS-резолв...",
            phase_tls13: "Фаза 1/3: TLS 1.3...",
            phase_tls12: "Фаза 2/3: TLS 1.2...",
            phase_http: "Фаза 3/3: HTTP...",
            checking_status: "Проверка...",
            phase_sni_base: "Фаза 1/2: Базовая проверка...",
            phase_sni_parallel: "Фаза 2/2: Параллельный перебор SNI для {} AS (батч {}, топ-{})...",
        },
        Language::Fa => Messages {
            banner_subtitle: "موتور بومی تشخیص فیلترینگ و بازرسی عمیق بسته‌ها (DPI)",
            netinfo_title: "اطلاعات شبکه و سیستم",
            dns_title: "وضعیت دسترسی به کارگزارهای DNS:",
            domain_title: "نتایج بررسی دامنه‌ها (TLS / SNI):",
            tcp16_title: "نتایج بررسی خنق پنجره TCP 16-20 KB:",
            telegram_title: "وضعیت دسترسی به سرورهای تلگرام:",
            summary_title: "خلاصه نتایج",
            resolver: "کارگزار DNS",
            status: "وضعیت",
            ip_count: "تعداد IP",
            latency: "تأخیر",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "دامنه",
            stage: "مرحله",
            bytes: "بایت‌ها (ارسال/دریافت)",
            duration: "مدت زمان",
            detail: "جزئیات",
            target: "هدف",
            provider: "ارائه‌دهنده",
            region: "منطقه",
            speed: "سرعت",
            bypass_tools: "ابزارهای دور زدن فیلترینگ",
            gateway: "دروازه پیش‌فرض",
            syn_drop_desc: "SYN DROP (تجهیزات فیلترینگ بسته SYN را انداختند)",
            tcp_rst_desc: "TCP RST (اتصال TCP توسط فیلترینگ ریست شد)",
            tls_rst_desc: "TLS RST (قطع اتصال TLS پس از ClientHello / مسدودسازی SNI)",
            tls_drop_desc: "TLS DROP (انداختن بسته‌ها هنگام مصافحه TLS)",
            tls_alert_desc: "TLS ALERT (خطای گواهی امنیتی یا اخطار صریح TLS)",
            http_blocked_desc: "HTTP BLOCK (هدایت به صفحه پیوندها یا فیلترینگ)",
            tcp16_drop_desc: "TCP16 DROP (محدودسازی پهنای باند پنجره TCP)",
            unreachable_desc: "UNREACHABLE (شبکه یا میزبان در دسترس نیست)",
            menu_title: "پارامترها و انتخاب آزمون‌ها",
            menu_language: "Language",
            menu_ip_version: "نسخه IP",
            menu_concurrency: "هم‌زمانی",
            menu_hw_row: "سطر",
            menu_hw_change: "تغییر",
            menu_hw_tests: "آزمون‌ها",
            menu_hw_start: "شروع",
            menu_hw_quit: "خروج",
            menu_line_prompt: "انتخاب را وارد کنید [123]: ",
            menu_invalid_line: "ورودی نامعتبر است؛ آزمون‌های 1، 2 و 3 اجرا می‌شوند.",
            menu_need_one: "دست‌کم یک آزمون را انتخاب کنید",
            menu_test_netinfo: "اطلاعات شبکه و سیستم",
            menu_test_dns: "بررسی دسترسی به سرورهای DNS",
            menu_test_domains: "بررسی دسترسی به دامنه‌ها",
            menu_test_tcp: "بررسی انسداد TCP در بازه 16-20 KB",
            menu_test_sni: "جست‌وجوی SNIهای مجاز برای ASN",
            menu_test_telegram: "بررسی تلگرام (کندی/انسداد)",
            menu_test_legend: "راهنمای وضعیت‌ها",
            lang: Language::Fa,
            replies_label: "پاسخ",
            blocked_short: "مسدود",
            mixed_short: "ترکیبی",
            legend_title: "\nراهنمای وضعیت‌ها:\n",

            latest_version: "✓ آخرین نسخه",
            author: "نویسنده:",
            chat: "چت:",
            checking_updates: "بررسی به‌روزرسانی‌ها...",
            os: "سیستم‌عامل:",
            system_dns: "DNS سیستم:",
            active_interface: "رابط فعال:",
            inactive_dns: "DNS غیرفعال:",
            router_resolver: "ریزولور روتر",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "پروکسی WSL",
            wsl_network: "شبکه WSL:",
            local_bypass: "دور زدن DPI محلی در دستگاه:",
            not_detected: "یافت نشد",
            unavailable: "در دسترس نیست",

            dns_check_title: "بررسی در دسترس بودن سرورهای DNS",
            doh_endpoints: "نقاط پایانی DoH",
            dot_endpoints: "نقاط پایانی DoT",
            udp_endpoints: "نقاط پایانی UDP",
            doh_min: "حداقل DoH",
            dot_min: "حداقل DoT",
            udp_min: "حداقل UDP",
            real_udp_resolver: "ریزولور واقعی UDP",
            spoofing: "جعل",
            timeout_label: "تایم‌اوت",
            egress_na: "خروج نامشخص",
            partial_dns_warn: "سرورهای DNS نیمه‌دردسترس (از دست رفتن بسته‌ها):",
            dns_fakeip_warn: "[!] پاسخ‌های DNS شامل FakeIP هستند\nبرای ارزیابی دقیق، پروکسی/FakeIP را خاموش کنید.",
            dns_intercept_warn: "[!] ارائه‌دهنده اینترنت شما پرس‌وجوهای DNS را رهگیری می‌کند\nپاسخ‌های UDP با صفحه مسدودسازی یا پاسخ‌های جعلی جایگزین می‌شوند",
            dns_stub_ip_label: "آدرس IP مسدودسازی ارائه‌دهنده: {}.",
            doh_recommendation: "توصیه: اگر هنوز انجام نداده‌اید، DoH را در دستگاه/روتر خود تنظیم کنید.",
            non_socks_proxy_warn: "پروکسی SOCKS5 نیست — پروب‌های UDP مستقیماً ارسال می‌شوند: رله UDP از طریق پروکسی HTTP ممکن نیست.\n",
            blocked_domains_label: "دامنه‌های مسدود شده برای بررسی:",
            unblocked_domains_label: "دامنه‌های مجاز برای بررسی:",
            dns_independent_warn: "هشدار: این یک بررسی مستقل است و از DNS پیکربندی شده شما استفاده نمی‌کند!\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] اطلاعات وضوح DNS:",
            traffic_fakeip: "ترافیک توسط Fake-IP رهگیری می‌شود: برای {} دامنه",
            dns_isp_stub: "DNS آدرس صفحه مسدودسازی را برگرداند ({}): برای {} دامنه",
            dns_local_ip: "DNS آدرس‌های محلی برگرداند (AdGuard/hosts?): ({}): برای {} دامنه",
            dns_fail_detected: "برای {} سایت خطای DNS FAIL شناسایی شد",
            doh_flush_guide: "توصیه: DoH را روی دستگاه و روتر خود تنظیم کنید\n\nپس از تنظیم، حافظه پنهان DNS را پاک کنید:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "بررسی مسدودسازی TCP 16-20KB",
            tcp_mixed_warn: "نتایج متناقض نشان‌دهنده متعادل‌سازی بار DPI است",
            no_port_443_targets: "هیچ هدفی با پورت ۴۴۳ برای تست SNI سفید وجود ندارد.\n",
            no_as_blocked: "هیچ AS مسدود نشده است — نیازی به جستجوی SNI نیست.\n",
            ban_after_label: "  ⚠ مسدود پس از",
            ban_rate_limit: "مسدود/محدودیت نرخ",
            sni_not_found: "× SNI یافت نشد (همه مسدود هستند)",
            whitelist_found_summary: "SNI سفید پیدا شد: در {} از {} AS مسدود شده",
            whitelist_none_summary: "هیچ SNI سفیدی برای هیچ‌یک از {} AS مسدود شده پیدا نشد",
            whitelist_skipped: "فایل whitelist_sni.txt خالی است یا یافت نشد — تست ۴ رد شد.\n",

            telegram_check_title: "بررسی دسترسی به تلگرام",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "پینگ",
            download_label: "دانلود",
            upload_label: "آپلود   ",
            peak_label: "اوج",
            avg_label: "میانگین",
            stall_after: "، قطع پس از {} ثانیه",
            ms_unit: "میلی‌ثانیه",

            summary_dns_avail: "دسترسی به DNS",
            summary_resolver_hijack: "جعل ریزولور",
            summary_all: "همه",
            summary_fakeip_resp: "پاسخ‌های FakeIP",
            summary_ans_hijack: "جعل پاسخ",
            summary_domains: "دامنه‌ها",
            summary_tg_download: "دانلود تلگرام",
            summary_tg_upload: "آپلود تلگرام",
            summary_tg_datacenters: "دیتاسنترهای تلگرام",

            menu_control_repeat: "تکرار",
            menu_control_menu: "منو",
            menu_control_export: "خروجی",
            menu_control_exit: "خروج",
            report_saved: "✓ گزارش در {} ذخیره شد",
            report_save_fail: "خطا در ذخیره فایل: {}",
            invalid_tests_flag: "مقدار نامعتبر برای --tests: '{}'. فقط ارقام 0-6 مجاز است.",
            invalid_concurrency_flag: "پارامتر --concurrency باید یک عدد صحیح >= 1 باشد.",
            tui_unavailable: "TUI در این ترمینال در دسترس نیست. با پارامترها اجرا کنید، مثلاً: dpi-detector -t 1,2,3 --batch (به dpi-detector --help مراجعه کنید).",
            ipv6_not_configured: "خطا: حالت IPv6 انتخاب شده اما در سیستم پیکربندی نشده است.",
            ipv6_switch_hint: "تغییر به IPv4: IP_VERSION: ipv4 در config.yml یا کلیدهای جهت‌نما در منو.",
            fetching_net_info: "دریافت اطلاعات شبکه...",
            net_info_unavailable: "اطلاعات شبکه در دسترس نیست.\n",
            domains_check_header: "بررسی در دسترس بودن دامنه‌ها",
            targets_label: "اهداف",
            phase_dns: "مرحله 0/3: وضوح DNS...",
            phase_tls13: "مرحله 1/3: TLS 1.3...",
            phase_tls12: "مرحله 2/3: TLS 1.2...",
            phase_http: "مرحله 3/3: HTTP...",
            checking_status: "در حال بررسی...",
            phase_sni_base: "مرحله 1/2: بررسی پایه...",
            phase_sni_parallel: "مرحله 2/2: جستجوی موازی SNI برای {} AS (دسته {}، برتر-{})...",
        },
        Language::Zh => Messages {
            banner_subtitle: "Rust 原生 DPI 审查与网络阻断诊断引擎",
            netinfo_title: "网络与系统信息",
            dns_title: "DNS 解析器可用性测试:",
            domain_title: "TLS / SNI 域名阻断探测结果:",
            tcp16_title: "TCP 16–20 KB 窗口限制探测结果:",
            telegram_title: "Telegram 数据中心可用性:",
            summary_title: "诊断汇总",
            resolver: "解析服务器",
            status: "状态",
            ip_count: "IP数量",
            latency: "延迟",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "域名",
            stage: "阶段",
            bytes: "流量 (发送/接收)",
            duration: "耗时",
            detail: "详情",
            target: "目标",
            provider: "服务商",
            region: "区域",
            speed: "速度",
            bypass_tools: "DPI 绕过工具",
            gateway: "默认网关",
            syn_drop_desc: "SYN DROP (审查设备丢弃了 TCP SYN 报文)",
            tcp_rst_desc: "TCP RST (握手期间连接被审查设备重置)",
            tls_rst_desc: "TLS RST (发送 ClientHello / SNI 后被重置)",
            tls_drop_desc: "TLS DROP (TLS 握手过程被丢弃)",
            tls_alert_desc: "TLS ALERT (证书错误或 TLS Alert 告警)",
            http_blocked_desc: "HTTP BLOCK (检测到重定向至运营商拦截页面)",
            tcp16_drop_desc: "TCP16 DROP (大窗口传输被限制或切断)",
            unreachable_desc: "UNREACHABLE (网络不可达)",
            menu_title: "参数与测试选择",
            menu_language: "Language",
            menu_ip_version: "IP 版本",
            menu_concurrency: "并发数",
            menu_hw_row: "行",
            menu_hw_change: "修改",
            menu_hw_tests: "测试",
            menu_hw_start: "开始",
            menu_hw_quit: "退出",
            menu_line_prompt: "请输入选择 [123]: ",
            menu_invalid_line: "输入无效，运行测试 1、2、3。",
            menu_need_one: "请至少选择一项测试",
            menu_test_netinfo: "网络与系统信息",
            menu_test_dns: "DNS 服务器可用性检查",
            menu_test_domains: "域名可用性检查",
            menu_test_tcp: "TCP 16–20 KB 阻断检查",
            menu_test_sni: "ASN 白名单 SNI 发现",
            menu_test_telegram: "Telegram 检查 (限速/阻断)",
            menu_test_legend: "状态图例 (帮助)",
            lang: Language::Zh,
            replies_label: "响应",
            blocked_short: "阻断",
            mixed_short: "混合",
            legend_title: "\n状态图例说明:\n",

            latest_version: "✓ 最新版本",
            author: "作者:",
            chat: "群聊:",
            checking_updates: "正在检查更新...",
            os: "操作系统:",
            system_dns: "系统 DNS:",
            active_interface: "活动接口:",
            inactive_dns: "非活动 DNS:",
            router_resolver: "路由器解析器",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "WSL 代理",
            wsl_network: "WSL 网络:",
            local_bypass: "设备本地 DPI 绕过:",
            not_detected: "未检测到",
            unavailable: "不可用",

            dns_check_title: "DNS 服务器可用性检查",
            doh_endpoints: "DoH 端点",
            dot_endpoints: "DoT 端点",
            udp_endpoints: "UDP 端点",
            doh_min: "DoH 最小",
            dot_min: "DoT 最小",
            udp_min: "UDP 最小",
            real_udp_resolver: "真实 UDP 解析器",
            spoofing: "劫持/篡改",
            timeout_label: "超时",
            egress_na: "出口不可用",
            partial_dns_warn: "部分可用的 DNS 服务器 (丢包):",
            dns_fakeip_warn: "[!] DNS 响应包含 FakeIP\n为了进行准确的 DNS 评估，请在测试期间关闭代理/FakeIP。",
            dns_intercept_warn: "[!] 您的互联网服务提供商拦截了 DNS 查询\nISP 将 UDP DNS 响应替换为封锁页面或虚假 NXDOMAIN/EMPTY/TIMEOUT",
            dns_stub_ip_label: "ISP 封锁页面 IP - {}。",
            doh_recommendation: "建议: 如果尚未配置，请在设备/路由器上配置 DoH。",
            non_socks_proxy_warn: "代理不是 SOCKS5 — UDP 探测直接发起: 无法通过 HTTP 代理进行 UDP 中继。\n",
            blocked_domains_label: "用于测试的被封锁域名:",
            unblocked_domains_label: "用于测试的未封锁域名:",
            dns_independent_warn: "注意: 这是独立测试，不使用您本地配置的 DNS！\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] DNS 解析信息:",
            traffic_fakeip: "流量被 Fake-IP 拦截: 共 {} 个域名",
            dns_isp_stub: "DNS 返回了 ISP 封锁页面 IP ({}): 共 {} 个域名",
            dns_local_ip: "DNS 返回了本地 IP (AdGuard/hosts?): ({}): 共 {} 个域名",
            dns_fail_detected: "共 {} 个站点检测到 DNS FAIL",
            doh_flush_guide: "建议: 在您的设备和路由器上配置 DoH\n\n配置完成后刷新 DNS 缓存:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "TCP 16–20 KB 阻断检查",
            tcp_mixed_warn: "混合结果表明运营商存在 DPI 负载均衡",
            no_port_443_targets: "没有用于白名单 SNI 测试的 443 端口目标。\n",
            no_as_blocked: "没有 AS 被封锁 — 无需发现白名单 SNI。\n",
            ban_after_label: "  ⚠ 随后封禁",
            ban_rate_limit: "封禁/限速",
            sni_not_found: "× 未找到可用 SNI (均被阻断)",
            whitelist_found_summary: "找到白名单 SNI: {} / {} 个被封锁的 AS",
            whitelist_none_summary: "未找到适用于任何 {} 个被封锁 AS 的白名单 SNI",
            whitelist_skipped: "文件 whitelist_sni.txt 为空或未找到 — 跳过测试 4。\n",

            telegram_check_title: "Telegram 可用性检查",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "延迟",
            download_label: "下载  ",
            upload_label: "上传  ",
            peak_label: "峰值",
            avg_label: "平均",
            stall_after: "，{}秒后中断",
            ms_unit: "毫秒",

            summary_dns_avail: "DNS 可用性",
            summary_resolver_hijack: "解析器劫持",
            summary_all: "全部",
            summary_fakeip_resp: "FakeIP 响应",
            summary_ans_hijack: "响应篡改",
            summary_domains: "域名",
            summary_tg_download: "TG 下载",
            summary_tg_upload: "TG 上传",
            summary_tg_datacenters: "TG 数据中心",

            menu_control_repeat: "重试",
            menu_control_menu: "菜单",
            menu_control_export: "导出",
            menu_control_exit: "退出",
            report_saved: "✓ 报告已保存到 {}",
            report_save_fail: "保存文件失败: {}",
            invalid_tests_flag: "--tests 的值无效: '{}'。仅允许数字 0-6。",
            invalid_concurrency_flag: "--concurrency 参数必须是 >= 1 的整数。",
            tui_unavailable: "此终端不支持 TUI。请携带参数运行，例如: dpi-detector -t 1,2,3 --batch (参见 dpi-detector --help)。",
            ipv6_not_configured: "错误: 已选择 IPv6 模式，但系统中未配置 IPv6。",
            ipv6_switch_hint: "请切换到 IPv4: 在 config.yml 中设置 IP_VERSION: ipv4 或在菜单中使用左右箭头。",
            fetching_net_info: "正在获取网络信息...",
            net_info_unavailable: "网络信息不可用。\n",
            domains_check_header: "域名可用性检查",
            targets_label: "目标",
            phase_dns: "阶段 0/3: DNS 解析...",
            phase_tls13: "阶段 1/3: TLS 1.3...",
            phase_tls12: "阶段 2/3: TLS 1.2...",
            phase_http: "阶段 3/3: HTTP...",
            checking_status: "正在检查...",
            phase_sni_base: "阶段 1/2: 基础检查...",
            phase_sni_parallel: "阶段 2/2: 针对 {} 个 AS 并行探测 SNI (批次 {}, 前 {})...",
        },
        Language::Es => Messages {
            banner_subtitle: "Motor Nativo en Rust para Diagnóstico de DPI y Censura",
            netinfo_title: "Información de Red y Sistema",
            dns_title: "Disponibilidad de Servidores DNS:",
            domain_title: "Resultados de Inspección de Dominios (TLS / SNI):",
            tcp16_title: "Resultados de Limitación de Ventana TCP 16–20 KB:",
            telegram_title: "Disponibilidad de Servidores de Telegram:",
            summary_title: "Resumen",
            resolver: "Servidor DNS",
            status: "Estado",
            ip_count: "Núm. IPs",
            latency: "Latencia",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Dominio",
            stage: "Etapa",
            bytes: "Bytes (Tx/Rx)",
            duration: "Duración",
            detail: "Detalle",
            target: "Objetivo",
            provider: "Proveedor",
            region: "Región",
            speed: "Velocidad",
            bypass_tools: "Herramientas de Bypass",
            gateway: "Puerta de Enlace",
            syn_drop_desc: "SYN DROP (El equipo de censura descartó el paquete TCP SYN)",
            tcp_rst_desc: "TCP RST (Conexión TCP reiniciada por DPI al conectar)",
            tls_rst_desc: "TLS RST (Reinicio tras ClientHello / bloqueo por SNI)",
            tls_drop_desc: "TLS DROP (Conexión descartada durante el handshake TLS)",
            tls_alert_desc: "TLS ALERT (Error de certificado o alerta fatal TLS)",
            http_blocked_desc: "HTTP BLOCK (Redirección a página de bloqueo detectada)",
            tcp16_drop_desc: "TCP16 DROP (Limitación de ventana o conexión cerrada)",
            unreachable_desc: "UNREACHABLE (Red o destino inalcanzable)",
            menu_title: "Parámetros y selección de pruebas",
            menu_language: "Language",
            menu_ip_version: "Versión IP",
            menu_concurrency: "Concurrencia",
            menu_hw_row: "fila",
            menu_hw_change: "cambiar",
            menu_hw_tests: "pruebas",
            menu_hw_start: "iniciar",
            menu_hw_quit: "salir",
            menu_line_prompt: "Ingrese su selección [123]: ",
            menu_invalid_line: "Entrada no válida, ejecutando pruebas 1, 2, 3.",
            menu_need_one: "Seleccione al menos una prueba",
            menu_test_netinfo: "Información de red y sistema",
            menu_test_dns: "Comprobación de disponibilidad de DNS",
            menu_test_domains: "Comprobación de disponibilidad de dominios",
            menu_test_tcp: "Comprobación de bloqueo TCP 16–20 KB",
            menu_test_sni: "Búsqueda de SNI permitidos para ASN",
            menu_test_telegram: "Comprobación de Telegram (ralentización/bloqueo)",
            menu_test_legend: "Leyenda de estados (ayuda)",
            lang: Language::Es,
            replies_label: "respuestas",
            blocked_short: "bloq.",
            mixed_short: "mixto",
            legend_title: "\nLeyenda de estados:\n",

            latest_version: "✓ Versión actual",
            author: "Autor:",
            chat: "Chat:",
            checking_updates: "Buscando actualizaciones...",
            os: "SO:",
            system_dns: "DNS del sistema:",
            active_interface: "Interfaz activa:",
            inactive_dns: "DNS inactivos:",
            router_resolver: "Resolvedor del router",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "proxy WSL",
            wsl_network: "Red WSL:",
            local_bypass: "Evasión local de DPI en el dispositivo:",
            not_detected: "no detectado",
            unavailable: "no disponible",

            dns_check_title: "Comprobación de disponibilidad de servidores DNS",
            doh_endpoints: "Extremos DoH",
            dot_endpoints: "Extremos DoT",
            udp_endpoints: "Extremos UDP",
            doh_min: "DoH mín",
            dot_min: "DoT mín",
            udp_min: "UDP mín",
            real_udp_resolver: "Resolvedor UDP real",
            spoofing: "Suplantación",
            timeout_label: "tiempo de espera",
            egress_na: "salida N/D",
            partial_dns_warn: "Servidores DNS parcialmente disponibles (pérdida de paquetes):",
            dns_fakeip_warn: "[!] Las respuestas DNS contienen FakeIP\nDesactive el proxy/FakeIP durante la prueba para una evaluación precisa.",
            dns_intercept_warn: "[!] Su proveedor de Internet intercepta las consultas DNS\nEl ISP sustituye las respuestas UDP por páginas de bloqueo o respuestas falsas",
            dns_stub_ip_label: "IP de la página de bloqueo del ISP: {}.",
            doh_recommendation: "Recomendación: configure DoH en su dispositivo/router si aún no lo ha hecho.",
            non_socks_proxy_warn: "El proxy no es SOCKS5 — Las pruebas UDP van directas: el relé UDP no es posible a través de proxy HTTP.\n",
            blocked_domains_label: "Dominios bloqueados para la prueba:",
            unblocked_domains_label: "Dominios desbloqueados para la prueba:",
            dns_independent_warn: "ATENCIÓN: ¡Esta es una comprobación independiente y no utiliza sus DNS configurados!\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] INFORMACIÓN DE RESOLUCIÓN DNS:",
            traffic_fakeip: "Tráfico interceptado por Fake-IP: en {} dominios",
            dns_isp_stub: "El DNS devolvió la IP de bloqueo del ISP ({}): en {} dominios",
            dns_local_ip: "El DNS devolvió IP locales (¿AdGuard/hosts?): ({}): en {} dominios",
            dns_fail_detected: "Se detectó DNS FAIL en {} sitios",
            doh_flush_guide: "Recomendación: Configure DoH en su dispositivo y router\n\nDespués de configurarlo, vacíe la caché de DNS:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "Comprobación de bloqueo TCP 16-20 KB",
            tcp_mixed_warn: "Los resultados mixtos indican balanceo de carga de DPI en el ISP",
            no_port_443_targets: "No hay objetivos con puerto 443 para la prueba de SNI.\n",
            no_as_blocked: "Ningún AS está bloqueado: no es necesario buscar SNI.\n",
            ban_after_label: "  ⚠ bloqueo tras",
            ban_rate_limit: "bloqueo/límite",
            sni_not_found: "× SNI no encontrado (todos bloqueados)",
            whitelist_found_summary: "SNI en lista blanca encontrados: en {} de {} AS bloqueados",
            whitelist_none_summary: "No se encontraron SNI en lista blanca para ninguno de los {} AS bloqueados",
            whitelist_skipped: "El archivo whitelist_sni.txt está vacío o no se encuentra: se omite la prueba 4.\n",

            telegram_check_title: "Comprobación de disponibilidad de Telegram",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Ping",
            download_label: "Descarga",
            upload_label: "Subida  ",
            peak_label: "pico",
            avg_label: "media",
            stall_after: ", corte tras {}s",
            ms_unit: "ms",

            summary_dns_avail: "Disponibilidad de DNS",
            summary_resolver_hijack: "Suplantación de resolvedor",
            summary_all: "Todos",
            summary_fakeip_resp: "Respuestas FakeIP",
            summary_ans_hijack: "Suplantación de respuestas",
            summary_domains: "Dominios",
            summary_tg_download: "Descarga TG",
            summary_tg_upload: "Subida TG",
            summary_tg_datacenters: "Centros de datos TG",

            menu_control_repeat: "Repetir",
            menu_control_menu: "Menú",
            menu_control_export: "Exportar",
            menu_control_exit: "Salir",
            report_saved: "✓ Informe guardado en {}",
            report_save_fail: "Error al guardar el archivo: {}",
            invalid_tests_flag: "Valor no válido para --tests: '{}'. Solo se permiten dígitos del 0 al 6.",
            invalid_concurrency_flag: "El parámetro --concurrency debe ser un entero >= 1.",
            tui_unavailable: "TUI no está disponible en este terminal. Ejecute con parámetros, p. ej.: dpi-detector -t 1,2,3 --batch (consulte dpi-detector --help).",
            ipv6_not_configured: "Error: se seleccionó el modo IPv6, pero IPv6 no está configurado en el sistema.",
            ipv6_switch_hint: "Cambie a IPv4: IP_VERSION: ipv4 en config.yml o flechas ← → en el menú.",
            fetching_net_info: "Obteniendo información de red...",
            net_info_unavailable: "Información de red no disponible.\n",
            domains_check_header: "Comprobación de disponibilidad de dominios",
            targets_label: "Objetivos",
            phase_dns: "Fase 0/3: Resolución DNS...",
            phase_tls13: "Fase 1/3: TLS 1.3...",
            phase_tls12: "Fase 2/3: TLS 1.2...",
            phase_http: "Fase 3/3: HTTP...",
            checking_status: "Comprobando...",
            phase_sni_base: "Fase 1/2: Comprobación básica...",
            phase_sni_parallel: "Fase 2/2: Búsqueda paralela de SNI para {} AS (lote {}, top-{})...",
        },
        Language::Ar => Messages {
            banner_subtitle: "محرك رست الأصلي لتشخيص فحص الحزم العميق (DPI) والحجب",
            netinfo_title: "معلومات الشبكة والنظام",
            dns_title: "مدى توفر خوادم DNS:",
            domain_title: "نتائج فحص النطاقات عبر (TLS / SNI):",
            tcp16_title: "نتائج فحص خنق حزم TCP 16-20 KB:",
            telegram_title: "مدى توفر مراكز بيانات تيليجرام:",
            summary_title: "الملخص",
            resolver: "خادم DNS",
            status: "الحالة",
            ip_count: "عدد العناوين",
            latency: "التأخير",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "النطاق",
            stage: "المرحلة",
            bytes: "البيانات (إرسال/استقبال)",
            duration: "المدة",
            detail: "التفاصيل",
            target: "الهدف",
            provider: "المزود",
            region: "المنطقة",
            speed: "السرعة",
            bypass_tools: "أدوات تجاوز الحجب",
            gateway: "البوابة الافتراضية",
            syn_drop_desc: "SYN DROP (تم إسقاط حزمة SYN بواسطة نظام الحجب)",
            tcp_rst_desc: "TCP RST (تمت إعادة تعيين اتصال TCP بواسطة DPI)",
            tls_rst_desc: "TLS RST (إعادة تعيين بعد إرسال ClientHello / حجب SNI)",
            tls_drop_desc: "TLS DROP (تم إسقاط الاتصال أثناء مصافحة TLS)",
            tls_alert_desc: "TLS ALERT (خطأ في الشهادة أو تنبيه TLS فادح)",
            http_blocked_desc: "HTTP BLOCK (تم اكتشاف التوجيه إلى صفحة الحجب)",
            tcp16_drop_desc: "TCP16 DROP (تم خنق نافذة الإرسال أو إسقاط الاتصال)",
            unreachable_desc: "UNREACHABLE (الشبكة أو المضيف غير متاح)",
            menu_title: "المعلمات واختيار الاختبارات",
            menu_language: "Language",
            menu_ip_version: "إصدار IP",
            menu_concurrency: "التزامن",
            menu_hw_row: "سطر",
            menu_hw_change: "تغییر",
            menu_hw_tests: "اختبارات",
            menu_hw_start: "بدء",
            menu_hw_quit: "خروج",
            menu_line_prompt: "أدخل الاختيار [123]: ",
            menu_invalid_line: "إدخال غير صالح، سيتم تشغيل الاختبارات 1 و2 و3.",
            menu_need_one: "اختر اختبارًا واحدًا على الأقل",
            menu_test_netinfo: "معلومات الشبكة والنظام",
            menu_test_dns: "فحص توفر خوادم DNS",
            menu_test_domains: "فحص توفر النطاقات",
            menu_test_tcp: "فحص حجب TCP بحجم 16-20 KB",
            menu_test_sni: "اكتشاف SNI المسموحة لرقم ASN",
            menu_test_telegram: "فحص تيليجرام (تقييد/حجب)",
            menu_test_legend: "دليل الحالات (مساعدة)",
            lang: Language::Ar,
            replies_label: "استجابات",
            blocked_short: "محجوب",
            mixed_short: "مختلط",
            legend_title: "\nدليل الحالات:\n",

            latest_version: "✓ أحدث إصدار",
            author: "المؤلف:",
            chat: "الدردشة:",
            checking_updates: "جارٍ التحقق من التحديثات...",
            os: "نظام التشغيل:",
            system_dns: "DNS النظام:",
            active_interface: "الواجهة النشطة:",
            inactive_dns: "DNS غير نشط:",
            router_resolver: "محلل الراوتر",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "بروكسي WSL",
            wsl_network: "شبكة WSL:",
            local_bypass: "تجاوز DPI المحلي على الجهاز:",
            not_detected: "لم يتم اكتشافه",
            unavailable: "غير متوفر",

            dns_check_title: "فحص توفر خوادم DNS",
            doh_endpoints: "نقاط نهاية DoH",
            dot_endpoints: "نقاط نهاية DoT",
            udp_endpoints: "نقاط نهاية UDP",
            doh_min: "DoH أدنى",
            dot_min: "DoT أدنى",
            udp_min: "UDP أدنى",
            real_udp_resolver: "محلل UDP الحقيقي",
            spoofing: "تزييف",
            timeout_label: "مهلة",
            egress_na: "خروج غير متاح",
            partial_dns_warn: "خوادم DNS متاحة جزئيًا (فقدان الحزم):",
            dns_fakeip_warn: "[!] تحتوي استجابات DNS على FakeIP\nقم بتعطيل الوكيل/FakeIP أثناء الفحص لإجراء تقييم دقيق.",
            dns_intercept_warn: "[!] مزود خدمة الإنترنت الخاص بك يعترض استعلامات DNS\nيستبدل المزود استجابات UDP بصفحات الحجب أو استجابات وهمية",
            dns_stub_ip_label: "عنوان IP لصفحة حجب المزود: {}.",
            doh_recommendation: "توصية: قم بإعداد DoH على جهازك/الراوتر إذا لم تفعل ذلك بعد.",
            non_socks_proxy_warn: "الوكيل ليس SOCKS5 — مجسات UDP مباشرة: لا يمكن ترحيل UDP عبر وكيل HTTP.\n",
            blocked_domains_label: "النطاقات المحجوبة للفحص:",
            unblocked_domains_label: "النطاقات غير المحجوبة للفحص:",
            dns_independent_warn: "تنبيه: هذا فحص مستقل ولا يستخدم خوادم DNS التي قمت بتهيئتها!\n",

            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] معلومات تحليل DNS:",
            traffic_fakeip: "يتم اعتراض حركة المرور بواسطة Fake-IP: لـ {} نطاقات",
            dns_isp_stub: "أعاد DNS عنوان IP لصفحة حجب المزود ({}): لـ {} نطاقات",
            dns_local_ip: "أعاد DNS عناوين IP محلية (AdGuard/hosts؟): ({}): لـ {} نطاقات",
            dns_fail_detected: "تم اكتشاف DNS FAIL لـ {} مواقع",
            doh_flush_guide: "توصية: قم بإعداد DoH على جهازك والراوتر\n\nبعد الإعداد، امسح ذاكرة التخزين المؤقت لـ DNS:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",

            tcp16_check_title: "فحص حجب TCP 16-20 كيلوبايت",
            tcp_mixed_warn: "تشير النتائج المتباينة إلى موازنة حمل DPI لدى المزود",
            no_port_443_targets: "لا توجد أهداف بالمنفذ 443 لاختبار SNI للقائمة البيضاء.\n",
            no_as_blocked: "لم يتم حجب أي AS — لا داعي للبحث عن SNI.\n",
            ban_after_label: "  ⚠ حظر بعد",
            ban_rate_limit: "حظر/تقييد معدل",
            sni_not_found: "× لم يتم العثور على SNI (الكل محجوب)",
            whitelist_found_summary: "تم العثور على SNI أبيض: في {} من {} AS المحجوبة",
            whitelist_none_summary: "لم يتم العثور على SNI أبيض لأي من {} AS المحجوبة",
            whitelist_skipped: "الملف whitelist_sni.txt فارغ أو غير موجود — تم تخطي الاختبار 4.\n",

            telegram_check_title: "فحص توفر Telegram",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "بينغ",
            download_label: "التنزيل",
            upload_label: "الرفع   ",
            peak_label: "الذروة",
            avg_label: "متوسط",
            stall_after: "، انقطاع بعد {}ث",
            ms_unit: "مللي ثانية",

            summary_dns_avail: "توفر DNS",
            summary_resolver_hijack: "تزييف المحلل",
            summary_all: "الكل",
            summary_fakeip_resp: "استجابات FakeIP",
            summary_ans_hijack: "تزييف الإجابات",
            summary_domains: "النطاقات",
            summary_tg_download: "تنزيل TG",
            summary_tg_upload: "رفع TG",
            summary_tg_datacenters: "مراكز بيانات TG",

            menu_control_repeat: "إعادة",
            menu_control_menu: "القائمة",
            menu_control_export: "تصدير",
            menu_control_exit: "خروج",
            report_saved: "✓ تم حفظ التقرير في {}",
            report_save_fail: "فشل حفظ الملف: {}",
            invalid_tests_flag: "قيمة غير صالحة لـ --tests: '{}'. يُسمح فقط بالأرقام 0-6.",
            invalid_concurrency_flag: "يجب أن تكون المعلمة --concurrency عددًا صحيحًا >= 1.",
            tui_unavailable: "واجهة TUI غير متوفرة في هذا الطرفية. شغّل باستخدام المعلمات، مثل: dpi-detector -t 1,2,3 --batch (راجع dpi-detector --help).",
            ipv6_not_configured: "خطأ: تم تحديد وضع IPv6، لكن IPv6 غير مهيأ في النظام.",
            ipv6_switch_hint: "قم بالتبديل إلى IPv4: IP_VERSION: ipv4 في config.yml أو الأسهم ← → في القائمة.",
            fetching_net_info: "جارٍ جلب معلومات الشبكة...",
            net_info_unavailable: "معلومات الشبكة غير متوفرة.\n",
            domains_check_header: "فحص توفر النطاقات",
            targets_label: "الأهداف",
            phase_dns: "المرحلة 0/3: تحليل DNS...",
            phase_tls13: "المرحلة 1/3: TLS 1.3...",
            phase_tls12: "المرحلة 2/3: TLS 1.2...",
            phase_http: "المرحلة 3/3: HTTP...",
            checking_status: "جارٍ الفحص...",
            phase_sni_base: "المرحلة 1/2: الفحص الأساسي...",
            phase_sni_parallel: "المرحلة 2/2: البحث المتوازي عن SNI لـ {} AS (دفعة {}، أفضل {})...",
        },
    }
}

/// Prints the full diagnostic status legend (mirrors `cli/ui.py::print_legend`).
/// Terms stay Latin; descriptions follow the selected language (en/ru full,
/// other languages fall back to English descriptions).
pub fn print_legend(lang: Language, msg: &Messages) {
    println!("{}", format_bidi(msg.legend_title, lang));
    let sections = match lang {
        Language::Ru => legend_sections(),
        Language::Zh => legend_sections_zh(),
        Language::Es => legend_sections_es(),
        Language::Fa => legend_sections_fa(),
        Language::Ar => legend_sections_ar(),
        Language::En => legend_sections_en(),
    };
    for (section, items) in &sections {
        println!("  {}", format_bidi(section, lang));
        for (term, desc) in items {
            println!("    \x1b[36m{:<14}\x1b[0m \x1b[2m{}\x1b[0m", term, format_bidi(desc, lang));
        }
        println!();
    }
}

/// Full legend sections in Chinese.
pub fn legend_sections_zh() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "DPI 切断或篡改 TLS: EOF、错误记录、握手异常中断"),
            ("TLS MITM", "中间人攻击: 证书被篡改 (未知 CA、证书过期、域名不匹配)"),
            ("TLS BLOCK", "TLS 版本或整个协议被阻断 (protocol_version alert)"),
            ("TLS RST", "发送 ClientHello 后收到主动 TCP RST (TLS 握手被重置)"),
            ("TLS DROP", "TLS 握手超时 — 数据包被静默丢弃 (未收到 RST)"),
            ("UNKNOWN", "未知错误 (括号内为异常类型)"),
            ("NO TLS1.3", "服务器不支持 TLS 1.3 (对于老旧服务器属于正常现象)"),
        ]),
        ("— TCP / 连接 —", vec![
            ("TCP RST", "连接被重置 (收到来自审查设备或服务器的 TCP RST 报文)"),
            ("SYN DROP", "TCP 连接超时 — SYN 已发送但未收到回复"),
            ("ABORT", "连接异常中断 (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "TCP 连接被拒绝 (ECONNREFUSED)"),
            ("TIMEOUT", "超时: SYN 丢弃、读取超时或系统网络超时"),
            ("NET UNREACH", "网络不可达 (ICMP unreachable)"),
            ("HOST UNREACH", "主机不可达"),
            ("OS ERR", "其他系统级网络错误 (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "域名无法通过系统解析器成功解析"),
            ("DNS FAKE", "域名解析 IP 命中已知的运营商拦截页面"),
            ("TIMEOUT", "DNS 服务器在规定时间内未响应"),
            ("BLOCKED", "DoH 服务器被运营商阻断 (HTTP 请求失败)"),
            ("NXDOMAIN", "该 DNS 服务器确认该域名不存在"),
        ]),
        ("— HTTP / 阻断 —", vec![
            ("BLOCKED", "HTTP 451 — 因法律或监管原因不可访问"),
            ("ISP PAGE", "解析到的 IP 为运营商拦截页面 (DNS 劫持篡改)"),
            ("REDIR", "绿色 — 重定向至同一主域名/子域名 (正常)；红色 — 重定向至外部陌生域名 (可疑)"),
        ]),
        ("— TCP 16-20KB 测试 —", vec![
            ("DETECTED", "传输达到 14–36 KB 后连接被切断 (特征性窗口阻断)"),
            ("OK", "所有 10 次请求 (最高 40 KB) 均正常传输无阻断"),
        ]),
        ("— 其他 —", vec![
            ("OK", "站点可正常访问 (状态码 200–4xx 无阻断特征)"),
            ("UNKNOWN", "未知异常 (括号内为具体异常类型)"),
            ("READ TIMEOUT", "服务器接受了连接但未及时返回数据: DPI 切断/限速、丢包或服务器过载"),
            ("POOL TIMEOUT", "套接字连接池耗尽 — 请降低并发连接数"),
        ]),
    ]
}

/// Full legend sections in Spanish.
pub fn legend_sections_es() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "DPI interrumpe o manipula TLS: EOF, registro corrupto, fallo de handshake"),
            ("TLS MITM", "Man-in-the-Middle: certificado sustituido (CA desconocida, expirado, nombre incorrecto)"),
            ("TLS BLOCK", "Versión de TLS o protocolo bloqueado (alerta protocol_version)"),
            ("TLS RST", "TCP RST activo tras ClientHello (reinicio del handshake TLS)"),
            ("TLS DROP", "Tiempo de espera agotado en TLS — paquetes descartados silenciosamente"),
            ("UNKNOWN", "Error desconocido (tipo de excepción entre paréntesis)"),
            ("NO TLS1.3", "El servidor no admite TLS 1.3 (normal en servidores antiguos)"),
        ]),
        ("— TCP / Conexión —", vec![
            ("TCP RST", "Conexión reiniciada (paquete TCP RST del DPI o del servidor)"),
            ("SYN DROP", "Tiempo de espera agotado — SYN enviado sin respuesta"),
            ("ABORT", "Conexión abortada (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "Conexión TCP rechazada (ECONNREFUSED)"),
            ("TIMEOUT", "Tiempo agotado: SYN drop, lectura o tiempo del sistema"),
            ("NET UNREACH", "Sin ruta a la red (ICMP inalcanzable)"),
            ("HOST UNREACH", "Sin ruta al host"),
            ("OS ERR", "Otros errores del sistema operativo (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "El dominio no se resolvió mediante el resolvedor del sistema"),
            ("DNS FAKE", "La IP coincide con una página de bloqueo conocida del proveedor"),
            ("TIMEOUT", "El servidor DNS no respondió a tiempo"),
            ("BLOCKED", "Servidor DoH bloqueado por el proveedor (fallo HTTP)"),
            ("NXDOMAIN", "El dominio no existe según este servidor"),
        ]),
        ("— HTTP / Bloqueos —", vec![
            ("BLOCKED", "HTTP 451 — No disponible por razones legales"),
            ("ISP PAGE", "La IP resuelta es una página de bloqueo del proveedor"),
            ("REDIR", "Verde — redirección al mismo dominio (normal); Rojo — redirección a otro dominio (sospechoso)"),
        ]),
        ("— Prueba TCP 16-20KB —", vec![
            ("DETECTED", "Corte de conexión tras transferir 14–36 KB"),
            ("OK", "Las 10 solicitudes (hasta 40 KB) pasaron sin cortes"),
        ]),
        ("— Otros —", vec![
            ("OK", "Sitio accesible (200–4xx sin indicios de censura)"),
            ("UNKNOWN", "Error desconocido (tipo de excepción entre paréntesis)"),
            ("READ TIMEOUT", "El servidor aceptó la petición pero la respuesta no llegó a tiempo: corte/limitación DPI o sobrecarga"),
            ("POOL TIMEOUT", "Grupo de sockets agotado: reduzca la concurrencia"),
        ]),
    ]
}

/// Full legend sections in Farsi.
pub fn legend_sections_fa() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "تجهیزات DPI اتصال TLS را دستکاری یا قطع می‌کنند: EOF، رکورد خراب، لغو مصافحه"),
            ("TLS MITM", "حمله مرد میانی: گواهی جعلی (مرجع ناشناخته، منقضی، عدم تطابق نام میزبان)"),
            ("TLS BLOCK", "مسدودسازی نسخه یا کل پروتکل TLS (اخطار protocol_version)"),
            ("TLS RST", "بسته فعال TCP RST پس از ارسال ClientHello (ریست مصافحه TLS)"),
            ("TLS DROP", "اتمام مهلت مصافحه TLS — بسته‌ها بی سر و صدا دور انداخته شدند"),
            ("UNKNOWN", "خطای ناشناخته (نوع خطا در پرانتز)"),
            ("NO TLS1.3", "سرور از TLS 1.3 پشتیبانی نمی‌کند (طبیعی برای سرورهای قدیمی)"),
        ]),
        ("— TCP / اتصال —", vec![
            ("TCP RST", "اتصال ریست شد (بسته TCP RST از طرف فیلترینگ یا سرور)"),
            ("SYN DROP", "اتمام مهلت اتصال TCP — بسته SYN ارسال شد ولی پاسخی نیامد"),
            ("ABORT", "اتصال لغو شد (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "اتصال TCP رد شد (ECONNREFUSED)"),
            ("TIMEOUT", "اتمام مهلت: دور انداختن SYN، مهلت خواندن یا خطای سیستم"),
            ("NET UNREACH", "مسیر شبکه در دسترس نیست (ICMP unreachable)"),
            ("HOST UNREACH", "میزبان در دسترس نیست"),
            ("OS ERR", "سایر خطاهای سیستم‌عامل (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "دامنه از طریق کارگزار سیستم حل نشد"),
            ("DNS FAKE", "آدرس IP با صفحه فیلترینگ ارائه‌دهنده مطابقت دارد"),
            ("TIMEOUT", "سرور DNS در زمان مقرر پاسخ نداد"),
            ("BLOCKED", "سرور DoH توسط ارائه‌دهنده مسدود شده است"),
            ("NXDOMAIN", "به گفته این سرور، دامنه وجود ندارد"),
        ]),
        ("— HTTP / مسدودسازی —", vec![
            ("BLOCKED", "کد 451 HTTP — به دلایل قانونی در دسترس نیست"),
            ("ISP PAGE", "آدرس IP حل شده صفحه مسدودسازی ارائه‌دهنده است"),
            ("REDIR", "سبز — هدایت به همان دامنه (طبیعی)؛ قرمز — هدایت به دامنه بیگانه (مشکوک)"),
        ]),
        ("— آزمون TCP 16-20KB —", vec![
            ("DETECTED", "قطع اتصال پس از ارسال 14 تا 36 کیلوبایت"),
            ("OK", "هر 10 درخواست (تا 40 کیلوبایت) بدون قطعی انجام شدند"),
        ]),
        ("— سایر —", vec![
            ("OK", "سایت در دسترس است (کد 200–4xx بدون علائم فیلترینگ)"),
            ("UNKNOWN", "خطای ناشناخته (نوع خطا در پرانتز)"),
            ("READ TIMEOUT", "پاسخی از سرور در زمان مقرر نرسید: اختلال/کندی DPI، افت بسته یا بار سرور"),
            ("POOL TIMEOUT", "تکمیل ظرفیت سوکت‌ها — لطفاً هم‌زمانی را کاهش دهید"),
        ]),
    ]
}

/// Full legend sections in Arabic.
pub fn legend_sections_ar() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "نظام DPI يقطع أو يعبث بـ TLS: نهاية ملف غير متوقعة، سجل تالف، فشل المصافحة"),
            ("TLS MITM", "هجوم رجل في المنتصف: شهادة مزورة (جهة غير موثوقة، منتهية، عدم تطابق الاسم)"),
            ("TLS BLOCK", "حجب إصدار TLS أو البروتوكول بالكامل (تنبيه protocol_version)"),
            ("TLS RST", "حزمة TCP RST نشطة بعد ClientHello (إعادة تعيين مصافحة TLS)"),
            ("TLS DROP", "انتهاء مهلة مصافحة TLS — تم إسقاط الحزم بصمت"),
            ("UNKNOWN", "خطأ غير معروف (نوع الخطأ بين قوسين)"),
            ("NO TLS1.3", "الخادم لا يدعم TLS 1.3 (أمر طبيعي للخوادم القديمة)"),
        ]),
        ("— TCP / الاتصال —", vec![
            ("TCP RST", "تمت إعادة تعيين الاتصال (حزمة TCP RST من نظام الحجب أو الخادم)"),
            ("SYN DROP", "انتهاء مهلة اتصال TCP — تم إرسال SYN دون رد"),
            ("ABORT", "تم إحباط الاتصال (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "تم رفض اتصال TCP (ECONNREFUSED)"),
            ("TIMEOUT", "انتهاء المهلة: إسقاط SYN، مهلة القراءة، أو مهلة النظام"),
            ("NET UNREACH", "لا يوجد مسار إلى الشبكة (ICMP unreachable)"),
            ("HOST UNREACH", "المضيف غير متاح"),
            ("OS ERR", "أخطاء نظام التشغيل الأخرى (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "فشل تحليل النطاق عبر محلل النظام"),
            ("DNS FAKE", "يطابق عنوان IP صفحة حجب المزود المعروفة"),
            ("TIMEOUT", "لم يستجب خادم DNS في الوقت المحدد"),
            ("BLOCKED", "خادم DoH محجوب من قبل المزود"),
            ("NXDOMAIN", "النطاق غير موجود وفقًا لهذا الخادم"),
        ]),
        ("— HTTP / الحجب —", vec![
            ("BLOCKED", "رمز 451 HTTP — غير متاح لأسباب قانونية"),
            ("ISP PAGE", "عنوان IP الذي تم حله هو صفحة حجب المزود"),
            ("REDIR", "أخضر — إعادة توجيه لنفس النطاق (طبيعي)؛ أحمر — إعادة توجيه لنطاق خارجي (مريب)"),
        ]),
        ("— فحص TCP 16-20KB —", vec![
            ("DETECTED", "انقطاع الاتصال بعد إرسال 14-36 كيلوبايت"),
            ("OK", "اجتازت جميع الطلبات الـ 10 (حتى 40 كيلوبايت) دون انقطاع"),
        ]),
        ("— أخرى —", vec![
            ("OK", "الموقع متاح (200-4xx دون مؤشرات حجب)"),
            ("UNKNOWN", "خطأ غير معروف (نوع الاستثناء بين قوسين)"),
            ("READ TIMEOUT", "قبل الخادم الطلب لكن الاستجابة لم تصل في الوقت المناسب: خنق/قطع DPI أو حمل زائد"),
            ("POOL TIMEOUT", "استنفاد مجمع المقابس — يرجى تقليل التزامن"),
        ]),
    ]
}

/// Full legend sections in Russian (canonical, mirrors Python).
pub fn legend_sections() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "DPI обрывает или манипулирует TLS: EOF, bad record, handshake abort"),
            ("TLS MITM", "Man-in-the-Middle: подменён сертификат (Unknown CA, Cert expired, Hostname mismatch)"),
            ("TLS BLOCK", "Блокировка версии TLS или протокола целиком (protocol_version alert)"),
            ("TLS RST", "Активный TCP RST на ClientHello (сброс TLS-хендшейка)"),
            ("TLS DROP", "Таймаут TLS-хендшейка — пакеты молча отброшены (нет RST)"),
            ("UNKNOWN", "Неизвестная ошибка (в скобках — тип исключения)"),
            ("NO TLS1.3", "Сервер не поддерживает TLS 1.3 (норма для старых серверов)"),
        ]),
        ("— TCP / Соединение —", vec![
            ("TCP RST", "Соединение сброшено (TCP RST пакет от DPI или сервера)"),
            ("SYN DROP", "Таймаут TCP-соединения — SYN отправлен, ответа нет"),
            ("ABORT", "Соединение прервано (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "TCP соединение отклонено (ECONNREFUSED)"),
            ("TIMEOUT", "Таймаут: SYN Drop, Read timeout или OS timeout"),
            ("NET UNREACH", "Нет маршрута до сети (ICMP unreachable)"),
            ("HOST UNREACH", "Нет маршрута до хоста"),
            ("OS ERR", "Прочие OS-ошибки (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "Домен не разрешился через системный резолвер"),
            ("DNS FAKE", "IP домена совпадает с известной заглушкой провайдера"),
            ("TIMEOUT", "DNS-сервер не ответил в отведённое время"),
            ("BLOCKED", "DoH-сервер заблокирован провайдером (HTTP не прошёл)"),
            ("NXDOMAIN", "Домен не существует по мнению этого сервера"),
        ]),
        ("— HTTP / Блокировки —", vec![
            ("BLOCKED", "HTTP 451 — Недоступно по юридическим причинам"),
            ("ISP PAGE", "Resolved IP является заглушкой провайдера (DNS подмена)"),
            ("REDIR", "Зелёный — редирект на тот же домен/поддомен (норма); Красный — редирект на чужой домен (подозрительно)"),
        ]),
        ("— TCP 16-20KB тест —", vec![
            ("DETECTED", "Обрыв соединения после отправки 14–36 KB"),
            ("OK", "Все 10 запросов (до 40 КБ) прошли без обрыва"),
        ]),
        ("— Прочее —", vec![
            ("OK", "Сайт доступен (200–4xx без признаков блокировки)"),
            ("UNKNOWN", "Неизвестная ошибка (в скобках — тип исключения)"),
            ("READ TIMEOUT", "Сервер принял запрос, но ответ не пришёл вовремя: DPI-обрыв/замедление, потеря пакетов или перегрузка сервера"),
            ("POOL TIMEOUT", "Исчерпан пул сокетов — снизьте MAX_CONCURRENT"),
        ]),
    ]
}

/// Full legend sections in English.
pub fn legend_sections_en() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("— TLS / DPI —", vec![
            ("TLS DPI", "DPI tears down or tampers with TLS: EOF, bad record, handshake abort"),
            ("TLS MITM", "Man-in-the-Middle: certificate substituted (Unknown CA, Cert expired, Hostname mismatch)"),
            ("TLS BLOCK", "TLS version or protocol blocked wholesale (protocol_version alert)"),
            ("TLS RST", "Active TCP RST on ClientHello (TLS handshake reset)"),
            ("TLS DROP", "TLS handshake timeout — packets silently dropped (no RST)"),
            ("UNKNOWN", "Unknown error (exception type in parentheses)"),
            ("NO TLS1.3", "Server does not support TLS 1.3 (normal for old servers)"),
        ]),
        ("— TCP / Connection —", vec![
            ("TCP RST", "Connection reset (TCP RST from DPI or server)"),
            ("SYN DROP", "TCP connection timeout — SYN sent, no reply"),
            ("ABORT", "Connection aborted (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "TCP connection refused (ECONNREFUSED)"),
            ("TIMEOUT", "Timeout: SYN drop, read timeout or OS timeout"),
            ("NET UNREACH", "No route to network (ICMP unreachable)"),
            ("HOST UNREACH", "No route to host"),
            ("OS ERR", "Other OS errors (errno)"),
        ]),
        ("— DNS —", vec![
            ("DNS FAIL", "Domain did not resolve via the system resolver"),
            ("DNS FAKE", "Domain IP matches a known provider stub"),
            ("TIMEOUT", "DNS server did not answer in time"),
            ("BLOCKED", "DoH server blocked by provider (HTTP failed)"),
            ("NXDOMAIN", "Domain does not exist according to this server"),
        ]),
        ("— HTTP / Blocks —", vec![
            ("BLOCKED", "HTTP 451 — Unavailable for legal reasons"),
            ("ISP PAGE", "Resolved IP is a provider stub (DNS spoofing)"),
            ("REDIR", "Green — redirect to the same domain/subdomain (normal); Red — redirect to a foreign domain (suspicious)"),
        ]),
        ("— TCP 16-20KB test —", vec![
            ("DETECTED", "Connection break after sending 14–36 KB"),
            ("OK", "All 10 requests (up to 40 KB) passed without a break"),
        ]),
        ("— Other —", vec![
            ("OK", "Site reachable (200–4xx with no block signs)"),
            ("UNKNOWN", "Unknown error (exception type in parentheses)"),
            ("READ TIMEOUT", "Server accepted the request but the reply never arrived: DPI break/throttling, packet loss or server overload"),
            ("POOL TIMEOUT", "Socket pool exhausted — lower MAX_CONCURRENT"),
        ]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_parsing() {
        assert_eq!(Language::from_code("ru"), Some(Language::Ru));
        assert_eq!(Language::from_code("en"), Some(Language::En));
        assert_eq!(Language::from_code("fa"), Some(Language::Fa));
        assert_eq!(Language::from_code("zh"), Some(Language::Zh));
        assert_eq!(Language::from_code("es"), Some(Language::Es));
        assert_eq!(Language::from_code("ar"), Some(Language::Ar));
        assert_eq!(Language::from_code("unknown"), None);
    }

    #[test]
    fn test_messages_coverage() {
        for lang in [
            Language::En,
            Language::Ru,
            Language::Fa,
            Language::Zh,
            Language::Es,
            Language::Ar,
        ] {
            let msg = get_messages(lang);
            assert!(!msg.banner_subtitle.is_empty());
            assert!(!msg.dns_title.is_empty());
            assert!(!msg.domain_title.is_empty());
            assert!(!msg.syn_drop_desc.is_empty());
            assert!(!msg.tls_rst_desc.is_empty());
            assert!(!msg.menu_title.is_empty());
            assert!(!msg.menu_language.is_empty());
            assert!(!msg.menu_ip_version.is_empty());
            assert!(!msg.menu_concurrency.is_empty());
            assert!(!msg.menu_hw_row.is_empty());
            assert!(!msg.menu_hw_change.is_empty());
            assert!(!msg.menu_hw_tests.is_empty());
            assert!(!msg.menu_hw_start.is_empty());
            assert!(!msg.menu_hw_quit.is_empty());
            assert!(!msg.menu_line_prompt.is_empty());
            assert!(!msg.menu_invalid_line.is_empty());
            assert!(!msg.menu_need_one.is_empty());
            assert!(!msg.latest_version.is_empty());
            assert!(!msg.author.is_empty());
            assert!(!msg.chat.is_empty());
            assert!(!msg.os.is_empty());
            assert!(!msg.system_dns.is_empty());
            assert!(!msg.active_interface.is_empty());
            assert!(!msg.dns_check_title.is_empty());
            assert!(!msg.doh_endpoints.is_empty());
            assert!(!msg.doh_min.is_empty());
            assert!(!msg.telegram_check_title.is_empty());
            assert!(!msg.summary_title.is_empty());
            for (d, field) in [
                ('0', msg.menu_test_netinfo),
                ('1', msg.menu_test_dns),
                ('2', msg.menu_test_domains),
                ('3', msg.menu_test_tcp),
                ('4', msg.menu_test_sni),
                ('5', msg.menu_test_telegram),
                ('6', msg.menu_test_legend),
            ] {
                assert!(!field.is_empty());
                assert_eq!(msg.menu_test_label(d), field);
            }
            assert_eq!(msg.menu_test_label('7'), "");
        }
    }

    #[test]
    fn test_format_bidi_farsi_and_arabic() {
        // LTR strings remain unchanged
        assert_eq!(format_bidi("English text", Language::En), "English text");
        assert_eq!(format_bidi("Русский текст", Language::Ru), "Русский текст");

        // Farsi words are shaped into connected cursive forms without reversing character order
        let shaped_exit = format_bidi("خروج", Language::Fa);
        assert_eq!(shaped_exit, "ﺧﺮﻭﺝ"); // Starts with initial KHA (ﺧ), ends with JEEM (ﺝ)

        let shaped_start = format_bidi("شروع", Language::Fa);
        assert_eq!(shaped_start, "ﺷﺮﻭﻉ"); // Starts with initial SHEEN (ﺷ), ends with AIN (ﻉ)

        let shaped_change = format_bidi("تغییر", Language::Fa);
        assert_eq!(shaped_change, "ﺗﻐﯿﯿﺮ"); // Starts with initial TEH (ﺗ)

        // Complex Farsi title
        let menu_title = "پارامترها و انتخاب آزمون‌ها";
        let shaped_title = format_bidi(menu_title, Language::Fa);
        assert!(shaped_title.starts_with('ﭘ')); // Starts with initial PEH (ﭘ), NOT reversed
        assert!(shaped_title.chars().any(|c| matches!(c, '\u{FB50}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}')));

        // Arabic string
        let ar_text = "المعلمات واختيار الاختبارات";
        let shaped_ar = format_bidi(ar_text, Language::Ar);
        assert!(shaped_ar.starts_with('ﺍ')); // Starts with ALEF, NOT reversed
    }

}
