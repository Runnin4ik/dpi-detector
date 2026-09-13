use std::env;
use serde::{Deserialize, Serialize};

mod details;
pub use details::{detail_lines, detail_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Ru,
    Zh,
    Fa,
}

impl Language {
    pub const ALL: [Self; 4] = [
        Self::En,
        Self::Ru,
        Self::Zh,
        Self::Fa,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Zh => "中文",
            Self::Fa => "Farsi",
        }
    }
    pub fn label_ascii(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Zh => "Chinese",
            Self::Fa => "Farsi",
        }
    }
    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "en" | "en_us" | "en_gb" | "english" => Some(Self::En),
            "ru" | "ru_ru" | "russian" => Some(Self::Ru),
            "zh" | "zh_cn" | "zh_hans" | "chinese" => Some(Self::Zh),
            "fa" | "fa_ir" | "farsi" | "persian" => Some(Self::Fa),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
            Self::Zh => "zh",
            Self::Fa => "fa",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
            Self::Zh => "简体中文",
            Self::Fa => "Farsi",
        }
    }

    pub fn is_rtl(&self) -> bool {
        false
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

/// Returns the text as-is. Kept for backwards compatibility with UI rendering callsites.
pub fn format_bidi(text: &str, _lang: Language) -> String {
    text.to_string()
}

/// Returns the text as-is. Kept for backwards compatibility with UI rendering callsites.
pub fn format_bidi_str(text: &str) -> String {
    text.to_string()
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

#[derive(Debug, Clone, Copy)]
pub struct Messages {
    pub banner_subtitle: &'static str,
    pub netinfo_title: &'static str,
    pub dns_title: &'static str,
    pub domain_title: &'static str,
    pub summary_title: &'static str,
    pub status: &'static str,
    pub available: &'static str,
    pub blocked: &'static str,
    pub domain: &'static str,
    pub stage: &'static str,
    pub bytes: &'static str,
    pub duration: &'static str,
    pub detail: &'static str,
    pub provider: &'static str,
    pub region: &'static str,
    pub bypass_tools: &'static str,
    pub gateway: &'static str,




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
    pub menu_test_burst: &'static str,
    pub burst_settings_title: &'static str,
    pub burst_field_attempts: &'static str,
    pub burst_field_timeout: &'static str,
    pub burst_field_domain: &'static str,
    pub burst_domain_placeholder: &'static str,
    pub burst_domain_default_hint: &'static str,
    pub burst_field_tls: &'static str,
    pub burst_field_http: &'static str,
    pub burst_field_profiles: &'static str,
    pub burst_profiles_all: &'static str,
    pub burst_title: &'static str,
    pub burst_attempts_label: &'static str,
    pub burst_summary_label: &'static str,
    pub burst_summary_value: &'static str,
    pub fingerprint_label: &'static str,
    pub fingerprint_note: &'static str,
    pub lang: Language,
    pub replies_label: &'static str,
    pub blocked_short: &'static str,
    pub mixed_short: &'static str,
    pub legend_title: &'static str,

    // Banner & Version
    pub latest_version: &'static str,
    pub author: &'static str,
    pub chat: &'static str,
    pub update_failed: &'static str,
    pub update_available: &'static str,
    pub update_current: &'static str,
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
    pub subnet_label: &'static str,
    pub ttlb_label: &'static str,
    pub org_label: &'static str,
    pub location_label: &'static str,
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
    /// Shown when the substitution reference came from DNS_TRUTH_FALLBACK
    /// instead of a live encrypted-DNS answer.
    pub dns_truth_fallback_note: &'static str,
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
    pub col_id: &'static str,
    pub col_asn: &'static str,
    pub batch_label: &'static str,
    pub dc_col: &'static str,
    pub ip_col: &'static str,
    pub ping_col: &'static str,
    pub download_label: &'static str,
    pub upload_label: &'static str,
    pub peak_label: &'static str,
    pub avg_label: &'static str,
    pub stall_after: &'static str,
    pub unit_mb_s: &'static str,
    pub unit_kb_s: &'static str,
    pub unit_b_s: &'static str,
    pub unit_mb: &'static str,
    pub unit_kb: &'static str,
    pub unit_b: &'static str,
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
    pub unavailable_ascii: &'static str,
    pub proxy_in_use: &'static str,
    pub tui_reason_stdin: &'static str,
    pub tui_reason_raw_mode: &'static str,
    pub crash_title: &'static str,
    pub crash_press_enter: &'static str,
    pub ipv6_not_configured: &'static str,
    pub ipv6_switch_hint: &'static str,
    pub fetching_net_info: &'static str,
    pub net_info_unavailable: &'static str,
    pub domains_check_header: &'static str,
    pub targets_label: &'static str,
    pub stages_label: &'static str,
    pub checking_status: &'static str,
    pub phase_sni_base: &'static str,
    pub phase_sni_parallel: &'static str,
    pub phase_telegram: &'static str,
    pub config_load_error_label: &'static str,
    pub config_warning_label: &'static str,
    pub cfg_warn_unknown_key: &'static str,
    pub cfg_warn_invalid_value: &'static str,
    pub cfg_warn_max_concurrent: &'static str,
    pub cfg_warn_ip_version: &'static str,
    pub cfg_warn_fingerprint: &'static str,
    pub cfg_warn_stub_threshold: &'static str,
    pub cfg_warn_upload_port: &'static str,
    pub cfg_warn_dc_port: &'static str,
    pub warn_unknown_lang: &'static str,
    pub warn_unknown_fingerprint: &'static str,
    pub warn_unknown_burst_axis: &'static str,
    pub press_enter_to_exit: &'static str,
    pub invalid_proxy_err: &'static str,
    pub dns_servers_empty_skip: &'static str,
    pub no_sni_label: &'static str,
    pub detail_timeout_word: &'static str,
    pub detail_read_timeout: &'static str,
    pub detail_write_timeout: &'static str,
    pub detail_at: &'static str,

    pub detail_isp_stub: &'static str,
    pub detail_local_ip: &'static str,
    pub cli_about: &'static str,
    pub cli_help: &'static str,
    pub cli_version: &'static str,
    pub cli_usage_heading: &'static str,
    pub cli_usage: &'static str,
    pub cli_options_heading: &'static str,
    pub cli_tests: &'static str,
    pub cli_json: &'static str,
    pub cli_verbose: &'static str,
    pub cli_lang: &'static str,
    pub cli_profile: &'static str,
    pub cli_legend: &'static str,
    pub cli_proxy: &'static str,
    pub cli_concurrency: &'static str,
    pub cli_domain: &'static str,
    pub cli_output: &'static str,
    pub cli_burst: &'static str,
    pub cli_burst_timeout: &'static str,
    pub cli_burst_profiles: &'static str,
    pub cli_burst_tls: &'static str,
    pub cli_burst_alpn: &'static str,
    pub cli_domains: &'static str,
    pub cli_tcp16: &'static str,
    pub cli_ascii: &'static str,
    pub cli_fingerprint: &'static str,

}

impl Messages {
    pub fn phase_text(&self, phase: crate::PhaseId) -> String {
        match phase {
            // Test 1 labels itself with the block tokens UDP/DoH/DoT/EGRESS,
            // which say more than any translation of "checking" would.
            crate::PhaseId::DnsAvailability => "DNS".to_string(),
            // Test 2 stages label themselves with their canonical token: they
            // share one line, where a sentence per stage would not fit.
            crate::PhaseId::DomainDns => crate::ProgressBlock::DomainDns.token().to_string(),
            crate::PhaseId::DomainTls13 => crate::ProgressBlock::DomainTls13.token().to_string(),
            crate::PhaseId::DomainTls12 => crate::ProgressBlock::DomainTls12.token().to_string(),
            crate::PhaseId::DomainHttp => crate::ProgressBlock::DomainHttp.token().to_string(),
            crate::PhaseId::Tcp16 => self.tcp16_check_title.to_string(),
            crate::PhaseId::SniBase => self.phase_sni_base.to_string(),
            crate::PhaseId::SniParallel { detected_as, batch, top_n } => {
                self.phase_sni_parallel
                    .replacen("{}", &detected_as.to_string(), 1)
                    .replacen("{}", &batch.to_string(), 1)
                    .replacen("{}", &top_n.to_string(), 1)
            }
            crate::PhaseId::Telegram => self.phase_telegram.to_string(),
        }
    }
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
            summary_title: "Summary",
            status: "Status",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Domain",
            stage: "Stage",
            bytes: "Bytes (Tx/Rx)",
            duration: "Duration",
            detail: "Detail",
            provider: "Provider",
            region: "Region",
            bypass_tools: "DPI Bypass Tools",
            gateway: "Default Gateway",
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
            menu_test_dns: "DNS server availability",
            menu_test_domains: "Website availability",
            menu_test_tcp: "CDN & hosting availability (16 KB test)",
            menu_test_sni: "Whitelist SNI discovery",
            menu_test_telegram: "Telegram availability",
            menu_test_legend: "Status legend (help)",
            menu_test_burst: "Fingerprint stress (burst)",
            burst_settings_title: "Test 7 settings",
            burst_field_attempts: "Simultaneous requests",
            burst_field_timeout: "Timeout, s",
            burst_field_domain: "Domain to test",
            burst_domain_placeholder: "Press → to start typing",
            burst_domain_default_hint: "By default — all domains",
            burst_field_tls: "TLS version",
            burst_field_http: "HTTP protocol",
            burst_field_profiles: "Fingerprints",
            burst_profiles_all: "all",
            burst_title: "Simultaneous handshakes (fingerprint stress)",
            burst_attempts_label: "Requests at once",
            burst_summary_label: "Stress",
            burst_summary_value: "{} of {} handshakes answered · hosts with losses: {}",
            fingerprint_label: "Fingerprint",
            fingerprint_note: "Each profile reproduces one pinned curl-impersonate shape: FIREFOX = firefox133, CHROME = chrome107 (also edge 99-101), SAFARI = safari155. All offer h2 and http/1.1 as browsers do. None is byte-for-byte a real browser — deeper fingerprinting (HTTP/2 settings, record timing) can still distinguish them.",
            lang: Language::En,
            replies_label: "replies",
            blocked_short: "blocked",
            mixed_short: "mixed",
            legend_title: "\nStatus legend:\n",

            latest_version: "✓ Latest version",
            author: "Author:",
            chat: "Chat:",

            update_failed: "× Failed to check for updates",
            update_available: "↑ New version available {}",
            update_current: "✓ Up to date",
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


            subnet_label: "Subnet:",
            ttlb_label: "TTLB:",
            org_label: "Org:",
            location_label: "Location:",
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
            dns_truth_fallback_note: "Reference IPs for part of the domains come from DNS_TRUTH_FALLBACK\n(config.yml): no encrypted DNS answered here, so they may be outdated.",
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

            col_id: "ID",
            col_asn: "ASN",
            batch_label: "batch",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Ping",
            download_label: "Download",
            upload_label: "Upload  ",
            peak_label: "peak",
            avg_label: "avg",
            stall_after: ", stall after {}s",

            unit_mb_s: "MB/s",
            unit_kb_s: "KB/s",
            unit_b_s: "B/s",
            unit_mb: "MB",
            unit_kb: "KB",
            unit_b: "B",
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
            invalid_tests_flag: "Invalid value for --tests: '{}'. Only digits 0-7 are allowed.",
            invalid_concurrency_flag: "The --concurrency parameter must be an integer >= 1.",
            tui_unavailable: "\r\nInteractive menu (TUI) is unavailable in this terminal [{}].\r\nRun diagnostics using command-line arguments:\r\n\x1b[36m  dpi-detector -t 1\x1b[0m       — DNS servers test\r\n\x1b[36m  dpi-detector -t 1,2,3\x1b[0m   — basic tests (DNS + sites + TCP16)\r\n\x1b[36m  dpi-detector -t 12345\x1b[0m   — all tests\r\n\x1b[36m  dpi-detector --help\x1b[0m     — full list of options\r\n\r\n",

            unavailable_ascii: "unavailable",
            proxy_in_use: "Proxy in use",
            tui_reason_stdin: "stdin is not a terminal (pipe or redirection)",
            tui_reason_raw_mode: "terminal does not support raw mode",
            crash_title: "\n=== DPI DETECTOR FATAL ERROR ===\n{}\n================================",
            crash_press_enter: "Press Enter to close...",
            ipv6_not_configured: "Error: IPv6 mode selected, but IPv6 is not configured on the system.",
            ipv6_switch_hint: "Switch family to IPv4: IP_VERSION: ipv4 in config.yml or left/right arrow in menu.",
            fetching_net_info: "Fetching network info...",
            net_info_unavailable: "Network information unavailable.\n",
            domains_check_header: "Domain Availability Check",
            targets_label: "Targets",
            stages_label: "Stages",
            checking_status: "Checking...",
            phase_sni_base: "Phase 1/2: Base check...",
            phase_sni_parallel: "Phase 2/2: Parallel SNI discovery for {} AS (batch {}, top-{})...",
            phase_telegram: "Telegram availability check",
            config_load_error_label: "Warning loading config.yml:",
            config_warning_label: "Notice config.yml:",
            cfg_warn_unknown_key: "Unknown config key: {}",
            cfg_warn_invalid_value: "{} has invalid value, using default",
            cfg_warn_max_concurrent: "MAX_CONCURRENT < 1, reset to 50",
            cfg_warn_ip_version: "IP_VERSION invalid, reset to ipv4",
            cfg_warn_fingerprint: "TLS_FINGERPRINT '{}' unknown, using rustls",
            cfg_warn_stub_threshold: "DNS_STUB_THRESHOLD out of range 1..50, reset to 2",
            cfg_warn_upload_port: "TELEGRAM_UPLOAD_PORT invalid, reset to 443",
            cfg_warn_dc_port: "TELEGRAM_DC_PORT invalid, reset to 443",

            warn_unknown_lang: "Warning: unknown --lang '{}' (expected ru|en|zh|fa|auto), using en",
            warn_unknown_fingerprint: "Warning: unknown --fingerprint '{}' (expected rustls|custom|chrome|safari), using {}",
            warn_unknown_burst_axis: "Warning: unknown {} '{}', using {}",
            press_enter_to_exit: "Press Enter to exit...",
            invalid_proxy_err: "Invalid proxy {}: {}\n",
            dns_servers_empty_skip: "DNS_AVAILABILITY_SERVERS not set in config.yml — test skipped.\n",
            no_sni_label: "(no SNI)",
            detail_timeout_word: "Timeout",
            detail_read_timeout: "Read timeout",
            detail_write_timeout: "Write timeout",
            detail_at: "at",
            detail_isp_stub: "ISP blockpage",
            detail_local_ip: "Local IP",
            cli_about: "High-performance DPI & censorship detection tool",
            cli_help: "Print help",
            cli_version: "Print version",
            cli_usage_heading: "Usage:",
            cli_usage: "dpi-detector [OPTIONS]",
            cli_options_heading: "Options",
            cli_tests: "Test suite selection string (e.g. '012', '1', '2')",
            cli_json: "Emit machine-readable JSON output",
            cli_verbose: "Enable verbose / debug logging",
            cli_lang: "Interface language (ru, en, zh, fa, auto). Default auto",
            cli_profile: "Regional censorship profile (ru, ir, cn, global)",
            cli_legend: "Display diagnostic status legend and exit",
            cli_proxy: "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080)",
            cli_concurrency: "Concurrency limit for parallel requests",
            cli_domain: "Specific domain(s) to test (repeat the flag: -d vk.com -d ya.ru)",
            cli_output: "Output file path to save report",
            cli_burst: "Fingerprint stress (test 7): simultaneous requests per round [default: 4]",
            cli_burst_timeout: "Test 7: timeout of one handshake, seconds [default: 8]",
            cli_burst_profiles: "Test 7 fingerprints: all|rustls,custom(firefox133),chrome(chrome107),safari(safari155) [default: all]",
            cli_burst_tls: "Test 7 TLS version: 1.2|1.3 [default: 1.3]",
            cli_burst_alpn: "Test 7 ALPN: h2 (offers h2 with the http/1.1 fallback)|http/1.1 (offers http/1.1 only) [default: h2]",
            cli_domains: "Path to custom domain list file",
            cli_tcp16: "Path to custom TCP16 target file",
            cli_ascii: "ASCII-only output for legacy consoles (no Unicode glyphs or borders)",
            cli_fingerprint: "TLS ClientHello fingerprint profile (rustls|custom|chrome|safari). custom = Firefox 133, chrome = Chrome 107 / Edge 99-101, safari = Safari 15.5-18.4 curl-impersonate shapes, all offering h2",
        },
        Language::Ru => Messages {
            banner_subtitle: "Детектор блокировок DPI и цензуры (Rust Native)",
            netinfo_title: "Информация о сети и системе",
            dns_title: "Доступность DNS-резолверов:",
            domain_title: "Результаты проверки доменов (TLS / SNI):",
            summary_title: "Итог",
            status: "Статус",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Домен",
            stage: "Стадия",
            bytes: "Байты (Tx/Rx)",
            duration: "Время",
            detail: "Детали",
            provider: "Провайдер",
            region: "Регион",
            bypass_tools: "Обходы DPI",
            gateway: "Основной шлюз",
            menu_title: "Параметры и выбор тестов",
            menu_language: "Язык",
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
            menu_test_dns: "Доступность DNS-серверов",
            menu_test_domains: "Доступность сайтов",
            menu_test_tcp: "Доступность CDN и хостингов (тест 16 KB)",
            menu_test_sni: "Поиск белых SNI",
            menu_test_telegram: "Доступность Telegram",
            menu_test_legend: "Легенда статусов (справка)",
            menu_test_burst: "Стресс отпечатка (burst)",
            burst_settings_title: "Настройки теста 7",
            burst_field_attempts: "Одновременных запросов",
            burst_field_timeout: "Таймаут, с",
            burst_field_domain: "Домен для тестирования",
            burst_domain_placeholder: "Переключитесь для ввода",
            burst_domain_default_hint: "По умолчанию — все домены",
            burst_field_tls: "Версия TLS",
            burst_field_http: "Протокол HTTP",
            burst_field_profiles: "Отпечатки",
            burst_profiles_all: "все",
            burst_title: "Одновременные рукопожатия (стресс отпечатка)",
            burst_attempts_label: "Запросов сразу",
            burst_summary_label: "Стресс",
            burst_summary_value: "{} из {} рукопожатий ответили · доменов с потерями: {}",
            fingerprint_label: "Отпечаток TLS",
            fingerprint_note: "Каждый профиль воспроизводит одну закреплённую форму curl-impersonate: FIREFOX = firefox133, CHROME = chrome107 (и edge 99-101), SAFARI = safari155. Все предлагают h2 и http/1.1, как браузеры. Ни один не является побайтовой копией настоящего браузера — более глубокий фингерпринтинг (настройки HTTP/2, тайминги записей) всё ещё может их отличить.",
            lang: Language::Ru,
            replies_label: "ответов",
            blocked_short: "блок.",
            mixed_short: "смеш.",
            legend_title: "\nЛегенда статусов:\n",

            latest_version: "✓ Актуальная версия",
            author: "Автор:",
            chat: "Чат:",

            update_failed: "× Не удалось проверить обновления",
            update_available: "↑ Доступна новая версия {}",
            update_current: "✓ Актуальная версия",
            checking_updates: "Проверка обновлений...",
            os: "ОС:",
            system_dns: "Системный DNS:",
            active_interface: "Активный интерфейс:",
            inactive_dns: "Неактивные DNS:",
            router_resolver: "Резолвер роутера",
            upstream_vpn: "Внешний VPN",
            wsl_proxy: "прокси WSL",
            wsl_network: "WSL-сеть:",
            local_bypass: "Локальный обход DPI на устройстве:",
            not_detected: "не обнаружен",
            unavailable: "недоступен",


            subnet_label: "Subnet:",
            ttlb_label: "TTLB:",
            org_label: "Org:",
            location_label: "Location:",
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
            dns_truth_fallback_note: "Эталонные IP части доменов взяты из DNS_TRUTH_FALLBACK\n(config.yml): зашифрованный DNS здесь не ответил, они могут быть устаревшими.",
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

            col_id: "ID",
            col_asn: "ASN",
            batch_label: "batch",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Пинг",
            download_label: "Скачивание",
            upload_label: "Загрузка  ",
            peak_label: "пик",
            avg_label: "ср.",
            stall_after: ", обрыв после {}с",

            unit_mb_s: "МБ/с",
            unit_kb_s: "КБ/с",
            unit_b_s: "Б/с",
            unit_mb: "МБ",
            unit_kb: "КБ",
            unit_b: "Б",
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
            invalid_tests_flag: "Недопустимое значение --tests: '{}'. Допустимы только цифры 0-7.",
            invalid_concurrency_flag: "Параметр --concurrency должен быть целым числом >= 1.",
            tui_unavailable: "\r\nИнтерактивное меню (TUI) недоступно в этом терминале [{}].\r\nЗапустите диагностику с параметрами:\r\n\x1b[36m  dpi-detector -t 1\x1b[0m       — проверка DNS-серверов\r\n\x1b[36m  dpi-detector -t 1,2,3\x1b[0m   — базовые тесты (DNS + сайты + TCP16)\r\n\x1b[36m  dpi-detector -t 12345\x1b[0m   — все тесты\r\n\x1b[36m  dpi-detector --help\x1b[0m     — список всех параметров\r\n\r\n",

            unavailable_ascii: "недоступен",
            proxy_in_use: "Используется прокси",
            tui_reason_stdin: "stdin не является терминалом (pipe или перенаправление)",
            tui_reason_raw_mode: "терминал не поддерживает raw mode",
            crash_title: "\n=== КРИТИЧЕСКАЯ ОШИБКА DPI DETECTOR ===\n{}\n====================================",
            crash_press_enter: "Нажмите Enter для закрытия...",
            ipv6_not_configured: "Ошибка: выбран режим IPv6, но IPv6 не настроен в системе.",
            ipv6_switch_hint: "Переключите семейство на IPv4: IP_VERSION: ipv4 в config.yml или стрелки ← → в меню.",
            fetching_net_info: "Получение сетевых данных...",
            net_info_unavailable: "Информация о сети недоступна.\n",
            domains_check_header: "Проверка доступности доменов",
            targets_label: "Целей",
            stages_label: "Этапы",
            checking_status: "Проверка...",
            phase_sni_base: "Фаза 1/2: Базовая проверка...",
            phase_sni_parallel: "Фаза 2/2: Параллельный перебор SNI для {} AS (батч {}, топ-{})...",
            phase_telegram: "Проверка доступности Telegram",
            config_load_error_label: "Внимание при загрузке config.yml:",
            config_warning_label: "Предупреждение config.yml:",
            cfg_warn_unknown_key: "Неизвестный ключ конфигурации: {}",
            cfg_warn_invalid_value: "{}: недопустимое значение, используется значение по умолчанию",
            cfg_warn_max_concurrent: "MAX_CONCURRENT < 1, сброшено на 50",
            cfg_warn_ip_version: "IP_VERSION недопустим, сброшено на ipv4",
            cfg_warn_fingerprint: "TLS_FINGERPRINT '{}' неизвестен, используется rustls",
            cfg_warn_stub_threshold: "DNS_STUB_THRESHOLD вне диапазона 1..50, сброшено на 2",
            cfg_warn_upload_port: "TELEGRAM_UPLOAD_PORT недопустим, сброшено на 443",
            cfg_warn_dc_port: "TELEGRAM_DC_PORT недопустим, сброшено на 443",

            warn_unknown_lang: "Предупреждение: неизвестный --lang '{}' (ожидается ru|en|zh|fa|auto), используется en",
            warn_unknown_fingerprint: "Предупреждение: неизвестный --fingerprint '{}' (ожидается rustls|custom|chrome|safari), используется {}",
            warn_unknown_burst_axis: "Предупреждение: неизвестное значение {} '{}', используется {}",
            press_enter_to_exit: "Нажмите Enter для выхода...",
            invalid_proxy_err: "Некорректный прокси {}: {}\n",
            dns_servers_empty_skip: "DNS_AVAILABILITY_SERVERS не задан в config.yml — тест пропущен.\n",
            no_sni_label: "(без SNI)",
            detail_timeout_word: "Таймаут",
            detail_read_timeout: "Таймаут чтения",
            detail_write_timeout: "Таймаут записи",
            detail_at: "на",
            detail_isp_stub: "Заглушка провайдера",
            detail_local_ip: "Локальный IP",
            cli_about: "Высокопроизводительный детектор DPI и цензуры",
            cli_help: "Показать справку",
            cli_version: "Показать версию",
            cli_usage_heading: "Использование:",
            cli_usage: "dpi-detector [ОПЦИИ]",
            cli_options_heading: "Опции",
            cli_tests: "Строка выбора тестов (например, '012', '1', '2')",
            cli_json: "Вывод в машиночитаемом JSON",
            cli_verbose: "Подробное / отладочное логирование",
            cli_lang: "Язык интерфейса (ru, en, zh, fa, auto). По умолчанию auto",
            cli_profile: "Региональный профиль цензуры (ru, ir, cn, global)",
            cli_legend: "Показать легенду статусов и выйти",
            cli_proxy: "URL SOCKS5-прокси (например, socks5://127.0.0.1:1080)",
            cli_concurrency: "Лимит параллельных запросов",
            cli_domain: "Конкретные домены для проверки (флаг можно повторять: -d vk.com -d ya.ru)",
            cli_output: "Путь к файлу отчёта",
            cli_burst: "Стресс отпечатка (тест 7): одновременных запросов за раунд [по умолчанию: 4]",
            cli_burst_timeout: "Тест 7: таймаут одного рукопожатия, секунды [по умолчанию: 8]",
            cli_burst_profiles: "Отпечатки для теста 7: all|rustls,custom(firefox133),chrome(chrome107),safari(safari155) [по умолчанию: all]",
            cli_burst_tls: "Версия TLS для теста 7: 1.2|1.3 [по умолчанию: 1.3]",
            cli_burst_alpn: "ALPN для теста 7: h2 (предлагает h2 с откатом на http/1.1)|http/1.1 (только http/1.1) [по умолчанию: h2]",
            cli_domains: "Путь к файлу со списком доменов",
            cli_tcp16: "Путь к файлу целей TCP16",
            cli_ascii: "Только ASCII для старых консолей (без Unicode-глифов и рамок)",
            cli_fingerprint: "Профиль отпечатка TLS ClientHello (rustls|custom|chrome|safari). custom — форма Firefox 133, chrome — Chrome 107 / Edge 99-101, safari — Safari 15.5-18.4 из curl-impersonate; все предлагают h2",
        },
        Language::Zh => Messages {
            banner_subtitle: "Rust 原生 DPI 审查与网络阻断诊断引擎",
            netinfo_title: "网络与系统信息",
            dns_title: "DNS 解析器可用性测试:",
            domain_title: "TLS / SNI 域名阻断探测结果:",
            summary_title: "诊断汇总",
            status: "状态",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "域名",
            stage: "阶段",
            bytes: "流量 (发送/接收)",
            duration: "耗时",
            detail: "详情",
            provider: "服务商",
            region: "区域",
            bypass_tools: "DPI 绕过工具",
            gateway: "默认网关",
            menu_title: "参数与测试选择",
            menu_language: "界面语言",
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
            menu_test_dns: "DNS 服务器可用性",
            menu_test_domains: "网站可用性",
            menu_test_tcp: "CDN 与主机可用性 (16 KB 测试)",
            menu_test_sni: "发现白名单 SNI",
            menu_test_telegram: "Telegram 可用性",
            menu_test_legend: "状态图例 (帮助)",
            menu_test_burst: "指纹压力测试 (burst)",
            burst_settings_title: "测试 7 设置",
            burst_field_attempts: "同时请求数",
            burst_field_timeout: "超时, 秒",
            burst_field_domain: "要测试的域名",
            burst_domain_placeholder: "按 → 开始输入",
            burst_domain_default_hint: "默认 — 全部域名",
            burst_field_tls: "TLS 版本",
            burst_field_http: "HTTP 协议",
            burst_field_profiles: "指纹",
            burst_profiles_all: "全部",
            burst_title: "同时握手 (指纹压力)",
            burst_attempts_label: "并发请求",
            burst_summary_label: "压力",
            burst_summary_value: "{} / {} 次握手得到响应 · 有丢包的域名: {}",
            fingerprint_label: "TLS 指纹",
            fingerprint_note: "每个配置复现一个固定的 curl-impersonate 形态：FIREFOX = firefox133，CHROME = chrome107（以及 edge 99-101），SAFARI = safari155。三者都像浏览器一样提供 h2 与 http/1.1。它们均非真实浏览器的逐字节复制，更深层的指纹识别（HTTP/2 设置、记录时序）仍可能将它们区分开。",
            lang: Language::Zh,
            replies_label: "响应",
            blocked_short: "阻断",
            mixed_short: "混合",
            legend_title: "\n状态图例说明:\n",

            latest_version: "✓ 最新版本",
            author: "作者:",
            chat: "群聊:",

            update_failed: "× 检查更新失败",
            update_available: "↑ 发现新版本 {}",
            update_current: "✓ 已是最新版本",
            checking_updates: "正在检查更新...",
            os: "操作系统:",
            system_dns: "系统 DNS:",
            active_interface: "活动接口:",
            inactive_dns: "非活动 DNS:",
            router_resolver: "路由器解析器",
            upstream_vpn: "上游 VPN",
            wsl_proxy: "WSL 代理",
            wsl_network: "WSL 网络:",
            local_bypass: "设备本地 DPI 绕过:",
            not_detected: "未检测到",
            unavailable: "不可用",


            subnet_label: "子网:",
            ttlb_label: "TTLB:",
            org_label: "组织:",
            location_label: "位置:",
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
            dns_truth_fallback_note: "部分域名的基准 IP 来自 DNS_TRUTH_FALLBACK\n(config.yml)：本网络加密 DNS 无应答，这些 IP 可能已过期。",
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

            col_id: "ID",
            col_asn: "ASN",
            batch_label: "批次",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "延迟",
            download_label: "下载  ",
            upload_label: "上传  ",
            peak_label: "峰值",
            avg_label: "平均",
            stall_after: "，{}秒后中断",

            unit_mb_s: "MB/s",
            unit_kb_s: "KB/s",
            unit_b_s: "B/s",
            unit_mb: "MB",
            unit_kb: "KB",
            unit_b: "B",
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
            invalid_tests_flag: "--tests 的值无效: '{}'。仅允许数字 0-7。",
            invalid_concurrency_flag: "--concurrency 参数必须是 >= 1 的整数。",
            tui_unavailable: "\r\n交互式菜单 (TUI) 在此终端中不可用 [{}]。\r\n请使用命令行参数运行诊断:\r\n\x1b[36m  dpi-detector -t 1\x1b[0m       — DNS 服务器测试\r\n\x1b[36m  dpi-detector -t 1,2,3\x1b[0m   — 基础测试 (DNS + 网站 + TCP16)\r\n\x1b[36m  dpi-detector -t 12345\x1b[0m   — 全部测试\r\n\x1b[36m  dpi-detector --help\x1b[0m     — 完整参数列表\r\n\r\n",

            unavailable_ascii: "unavailable",
            proxy_in_use: "使用代理",
            tui_reason_stdin: "标准输入不是终端（管道或重定向）",
            tui_reason_raw_mode: "终端不支持原始模式",
            crash_title: "\n=== DPI DETECTOR 致命错误 ===\n{}\n========================",
            crash_press_enter: "按 Enter 键关闭...",
            ipv6_not_configured: "错误: 已选择 IPv6 模式，但系统中未配置 IPv6。",
            ipv6_switch_hint: "请切换到 IPv4: 在 config.yml 中设置 IP_VERSION: ipv4 或在菜单中使用左右箭头。",
            fetching_net_info: "正在获取网络信息...",
            net_info_unavailable: "网络信息不可用。\n",
            domains_check_header: "域名可用性检查",
            targets_label: "目标",
            stages_label: "阶段",
            checking_status: "正在检查...",
            phase_sni_base: "阶段 1/2: 基础检查...",
            phase_sni_parallel: "阶段 2/2: 针对 {} 个 AS 并行探测 SNI (批次 {}, 前 {})...",
            phase_telegram: "Telegram 可用性检查",
            config_load_error_label: "加载 config.yml 时的警告:",
            config_warning_label: "config.yml 提示:",
            cfg_warn_unknown_key: "未知配置键: {}",
            cfg_warn_invalid_value: "{} 的值无效，改用默认值",
            cfg_warn_max_concurrent: "MAX_CONCURRENT < 1，已重置为 50",
            cfg_warn_ip_version: "IP_VERSION 无效，已重置为 ipv4",
            cfg_warn_fingerprint: "TLS_FINGERPRINT '{}' 未知，改用 rustls",
            cfg_warn_stub_threshold: "DNS_STUB_THRESHOLD 超出范围 1..50，已重置为 2",
            cfg_warn_upload_port: "TELEGRAM_UPLOAD_PORT 无效，已重置为 443",
            cfg_warn_dc_port: "TELEGRAM_DC_PORT 无效，已重置为 443",

            warn_unknown_lang: "警告: 未知的 --lang '{}'（应为 ru|en|zh|fa|auto），改用 en",
            warn_unknown_fingerprint: "警告: 未知的 --fingerprint '{}'（应为 rustls|custom|chrome|safari），改用 {}",
            warn_unknown_burst_axis: "警告: 未知的 {} '{}'，改用 {}",
            press_enter_to_exit: "按回车键退出...",
            invalid_proxy_err: "无效代理 {}: {}\n",
            dns_servers_empty_skip: "config.yml 中未设置 DNS_AVAILABILITY_SERVERS — 跳过测试。\n",
            no_sni_label: "(无 SNI)",
            detail_timeout_word: "超时",
            detail_read_timeout: "读取超时",
            detail_write_timeout: "写入超时",
            detail_at: "在",
            detail_isp_stub: "ISP 拦截页",
            detail_local_ip: "本地 IP",
            cli_about: "高性能 DPI 与网络审查检测工具",
            cli_help: "显示帮助",
            cli_version: "显示版本",
            cli_usage_heading: "用法:",
            cli_usage: "dpi-detector [选项]",
            cli_options_heading: "选项",
            cli_tests: "测试选择字符串（例如 '012'、'1'、'2'）",
            cli_json: "输出机器可读的 JSON",
            cli_verbose: "启用详细/调试日志",
            cli_lang: "界面语言（ru、en、zh、fa、auto）。默认 auto",
            cli_profile: "地区审查配置文件（ru、ir、cn、global）",
            cli_legend: "显示状态图例并退出",
            cli_proxy: "SOCKS5 代理 URL（例如 socks5://127.0.0.1:1080）",
            cli_concurrency: "并行请求的并发上限",
            cli_domain: "要测试的指定域名（可重复指定: -d vk.com -d ya.ru）",
            cli_output: "保存报告的输出文件路径",
            cli_burst: "指纹压力测试 (测试 7): 每轮同时请求数 [默认: 4]",
            cli_burst_timeout: "测试 7: 单次握手超时, 秒 [默认: 8]",
            cli_burst_profiles: "测试 7 的指纹: all|rustls,custom(firefox133),chrome(chrome107),safari(safari155) [默认: all]",
            cli_burst_tls: "测试 7 的 TLS 版本: 1.2|1.3 [默认: 1.3]",
            cli_burst_alpn: "测试 7 的 ALPN: h2（提供 h2 并回退 http/1.1）|http/1.1（仅 http/1.1）[默认: h2]",
            cli_domains: "自定义域名列表文件路径",
            cli_tcp16: "自定义 TCP16 目标文件路径",
            cli_ascii: "面向旧终端的纯 ASCII 输出（无 Unicode 符号或边框）",
            cli_fingerprint: "TLS ClientHello 指纹配置（rustls|custom|chrome|safari）。custom = Firefox 133，chrome = Chrome 107 / Edge 99-101，safari = Safari 15.5-18.4（curl-impersonate 形态），均提供 h2",
        },
        Language::Fa => Messages {
            banner_subtitle: "Motore boomi-e tashkhis-e filtering va barresi-e amigh-e packet ha (DPI)",
            netinfo_title: "Ettela'ate shabake va system",
            dns_title: "Vaziyat-e dastrasi be kargozarhaye DNS:",
            domain_title: "Natayej-e barresi-e domain ha (TLS / SNI):",
            summary_title: "Kholase-ye natayej",
            status: "Vaziyat",
            available: "AVAILABLE",
            blocked: "BLOCKED",
            domain: "Domain",
            stage: "Marhale",
            bytes: "Byte ha (ersal/daryaft)",
            duration: "Moddat-e zaman",
            detail: "Joz'iyat",
            provider: "Ara'e-dahande",
            region: "Mantaghe",
            bypass_tools: "Abarhaye door zadan-e filtering",
            gateway: "Darvaze-ye pishfarz",
            menu_title: "Tanzimat va entekhab-e test ha",
            menu_language: "Zaban",
            menu_ip_version: "IP version",
            menu_concurrency: "Teedade worker ha",
            menu_hw_row: "Peymayesh",
            menu_hw_change: "Taghir",
            menu_hw_tests: "Test ha",
            menu_hw_start: "Shoroo",
            menu_hw_quit: "Khorooj",
            menu_line_prompt: "Entekhab-e khod ra vared konid [123]: ",
            menu_invalid_line: "Voroodi-e na-motabar; test haye 1, 2, 3 ejra mishavand.",
            menu_need_one: "Hadaghal yek test ra entekhab konid",
            menu_test_netinfo: "Ettela'ate shabake va system",
            menu_test_dns: "DNS server haye dar dastras",
            menu_test_domains: "Website haye dar dastras",
            menu_test_tcp: "CDN va hosting haye dar dastras",
            menu_test_sni: "Jost o juye SNI haye whitelist",
            menu_test_telegram: "Dastrasi be Telegram",
            menu_test_legend: "Rahnemaye barname",
            menu_test_burst: "Stress-e fingerprint (burst)",
            burst_settings_title: "Tanzimat-e test 7",
            burst_field_attempts: "Darkhast haye hamzaman",
            burst_field_timeout: "Timeout, sanie",
            burst_field_domain: "Domain baraye test",
            burst_domain_placeholder: "Baraye neveshtan -> bezanid",
            burst_domain_default_hint: "Pishfarz - hame-ye domain ha",
            burst_field_tls: "Version-e TLS",
            burst_field_http: "Protocol-e HTTP",
            burst_field_profiles: "Fingerprint ha",
            burst_profiles_all: "hame",
            burst_title: "Mosafehe haye hamzaman (stress-e fingerprint)",
            burst_attempts_label: "Darkhast dar yek bar",
            burst_summary_label: "Stress",
            burst_summary_value: "{} az {} mosafehe javab dad | domain ba ziyan: {}",
            fingerprint_label: "Fingerprint",
            fingerprint_note: "Har profile yek shape-e pin-shode-ye curl-impersonate ra bazsazi mikonad: FIREFOX = firefox133, CHROME = chrome107 (va edge 99-101), SAFARI = safari155. Hame h2 va http/1.1 ra mesl-e browser ha pishnahad mikonand. Hich yek copy-e byte-be-byte-e yek browser-e vaghe-i nist - fingerprinting-e amigh-tar (HTTP/2 settings, record timing) hanuz mitavanad anha ra tafzil konad.",
            lang: Language::Fa,
            replies_label: "pasokh ha",
            blocked_short: "masdood",
            mixed_short: "tarkibi",
            legend_title: "\nRahnemaye vaziyat ha:\n",
            latest_version: "✓ Akharin noskhe",
            author: "Nivisande:",
            chat: "Goruh:",

            update_failed: "× Khata dar barresi-e update ha",
            update_available: "↑ Noskhe-ye jadid dar dastras ast {}",
            update_current: "✓ Akharin noskhe",
            checking_updates: "Barresi-e update...",
            os: "System-e amel:",
            system_dns: "DNS system:",
            active_interface: "Interface-e fa'al:",
            inactive_dns: "DNS-e gheyr-e fa'al:",
            router_resolver: "Resolver-e router",
            upstream_vpn: "Upstream VPN",
            wsl_proxy: "Proxy-e WSL",
            wsl_network: "Shabake-ye WSL:",
            local_bypass: "Door zadan-e mahalli-e DPI dar device:",
            not_detected: "peyda nashod",
            unavailable: "dar dastras nist",

            subnet_label: "Subnet:",
            ttlb_label: "TTLB:",
            org_label: "Org:",
            location_label: "Location:",
            dns_check_title: "Barresi-e dar dastras boodan-e serverhaye DNS",
            doh_endpoints: "Endpoint haye DoH",
            dot_endpoints: "Endpoint haye DoT",
            udp_endpoints: "Endpoint haye UDP",
            doh_min: "Hadaghal-e DoH",
            dot_min: "Hadaghal-e DoT",
            udp_min: "Hadaghal-e UDP",
            real_udp_resolver: "Resolver-e vaghe'i-e UDP",
            spoofing: "Ja'l",
            timeout_label: "mohlat",
            egress_na: "egress N/A",
            partial_dns_warn: "Serverhaye DNS ba dastrasi-e naghes (az dast raftan-e packet ha):",
            dns_truth_fallback_note: "IP haye reference baraye barkhi domain ha az DNS_TRUTH_FALLBACK\n(config.yml) miyayand: hich DNS-e encrypted pasokh nadad, pas momken ast ghadimi bashand.",
            dns_fakeip_warn: "[!] Pasokh haye DNS shamel-e FakeIP hastand\nBaraye arzyabi-e daghigh, dar tool-e test proxy/FakeIP ra khamoosh konid.",
            dns_intercept_warn: "[!] ISP shoma porsoju haye DNS ra intercept mikonad\nPasokh haye UDP ba blockpage ya pasokh haye ja'li jaygozin mishavand",
            dns_stub_ip_label: "IP-e blockpage-e ISP: {}.",
            doh_recommendation: "Tavsiye: agar emkan darad DoH ra rooye device ya router-e khod fa'al konid.",
            non_socks_proxy_warn: "Proxy az no'e SOCKS5 nist - probe haye UDP mostaghim ersal mishavand: enteghal-e UDP az tarigh-e HTTP proxy momken nist.\n",
            blocked_domains_label: "Domain haye masdood baraye barresi:",
            unblocked_domains_label: "Domain haye mojaz baraye barresi:",
            dns_independent_warn: "Tavajjoh: in yek test-e mostaghel ast va az DNS-e tanzim shode dar system-e shoma estefade nemikonad!\n",
            http: "HTTP",
            tls12: "TLS1.2",
            tls13: "TLS1.3",
            dns_info_title: "[i] Ettela'ate tahlil-e DNS:",
            traffic_fakeip: "Traffic tavasot-e Fake-IP intercept mishavad: baraye {} domain",
            dns_isp_stub: "DNS IP-e blockpage-e ISP ra bargardand ({}): baraye {} domain",
            dns_local_ip: "DNS IP haye mahalli ra bargardand (AdGuard/hosts?): ({}): baraye {} domain",
            dns_fail_detected: "Khatay-e DNS FAIL baraye {} site moshahede shod",
            doh_flush_guide: "Tavsiye: DoH ra rooye device va router-e khod tanzim konid\n\nPas az tanzim, cache-e DNS ra pak konid:\nWindows: ipconfig /flushdns\nmacOS: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder\nLinux: sudo resolvectl flush-caches\n",
            tcp16_check_title: "Barresi-e masdoodsazi-e TCP 16-20KB",
            tcp_mixed_warn: "Natayej-e tarkibi neshane-dahande-ye load balancing-e DPI-e ISP ast",
            no_port_443_targets: "Hich hadafi ba port-e 443 baraye test-e SNI-e whitelist vojud nadarad.\n",
            no_as_blocked: "Hich AS-i masdood nashode ast - niyazi be jost o juye SNI nist.\n",
            ban_after_label: "  ⚠ masdood ba'd az",
            ban_rate_limit: "masdood/rate-limit",
            sni_not_found: "× SNI peyda nashod (hame masdood hastand)",
            whitelist_found_summary: "SNI-e sefid peyda shod: dar {} az {} AS-e masdood",
            whitelist_none_summary: "Hich SNI-e sefidi baraye hich yek az {} AS-e masdood peyda nashod",
            whitelist_skipped: "File-e whitelist_sni.txt khali ast ya peyda nashod - test-e 4 nadide gerefte shod.\n",
            telegram_check_title: "Barresi-e dastrasi be Telegram",

            col_id: "ID",
            col_asn: "ASN",
            batch_label: "batch",
            dc_col: "DC",
            ip_col: "IP",
            ping_col: "Ping",
            download_label: "Download",
            upload_label: "Upload  ",
            peak_label: "peak",
            avg_label: "avg",
            stall_after: ", stall ba'd az {}s",

            unit_mb_s: "MB/s",
            unit_kb_s: "KB/s",
            unit_b_s: "B/s",
            unit_mb: "MB",
            unit_kb: "KB",
            unit_b: "B",
            ms_unit: "ms",
            summary_dns_avail: "Dastrasi be DNS",
            summary_resolver_hijack: "Ja'l-e resolver",
            summary_all: "Hame",
            summary_fakeip_resp: "Pasokh haye FakeIP",
            summary_ans_hijack: "Ja'l-e pasokh",
            summary_domains: "Domain ha",
            summary_tg_download: "Download-e Telegram",
            summary_tg_upload: "Upload-e Telegram",
            summary_tg_datacenters: "Datacenter haye Telegram",
            menu_control_repeat: "Tekrar",
            menu_control_menu: "Menu",
            menu_control_export: "Export",
            menu_control_exit: "Khorooj",
            report_saved: "✓ Gozaresh dar {} zakhire shod",
            report_save_fail: "Khata dar zakhire-e file: {}",
            invalid_tests_flag: "Meghdar-e na-motabar baraye --tests: '{}'. Faghat agham-e 0 ta 7 mojaz hastand.",
            invalid_concurrency_flag: "Parametr-e --concurrency bayad yek adad-e sahih >= 1 bashad.",
            tui_unavailable: "\r\nMenyuye interactive (TUI) dar in terminal dar dastras nist [{}].\r\nBarname ra ba parametr ha ejra konid:\r\n\x1b[36m  dpi-detector -t 1\x1b[0m       - test-e DNS server ha\r\n\x1b[36m  dpi-detector -t 1,2,3\x1b[0m   - test haye asasi (DNS + site ha + TCP16)\r\n\x1b[36m  dpi-detector -t 12345\x1b[0m   - hame-ye test ha\r\n\x1b[36m  dpi-detector --help\x1b[0m     - list-e kamel-e parametr ha\r\n\r\n",

            unavailable_ascii: "unavailable",
            proxy_in_use: "Proxy dar hal-e estefade ast",
            tui_reason_stdin: "stdin terminal nist (pipe ya redirect)",
            tui_reason_raw_mode: "terminal az raw mode poshtibani nemikonad",
            crash_title: "\n=== KHATA-YE KOLI DAR DPI DETECTOR ===\n{}\n=====================================",
            crash_press_enter: "Baraye bastan Enter ra bezanid...",
            ipv6_not_configured: "Khata: halat-e IPv6 entekhab shode ama rooye system tanzim nashode ast.",
            ipv6_switch_hint: "Taghir be IPv4: meghdar-e IP_VERSION: ipv4 dar config.yml ya ba kelid haye jahat-nama dar menu.",
            fetching_net_info: "Daryaft-e ettela'ate shabake...",
            net_info_unavailable: "Ettela'ate shabake dar dastras nist.\n",
            domains_check_header: "Barresi-e dastrasi be website ha",
            targets_label: "Hadaf ha",
            stages_label: "Marhale ha",
            checking_status: "Dar hal-e barresi...",
            phase_sni_base: "Marhale 1/2: barresi-e paye...",
            phase_sni_parallel: "Marhale 2/2: jost o juye movazi-e SNI baraye {} AS (daste {}, top-{})...",
            phase_telegram: "Barresi-e dastrasi be Telegram",
            config_load_error_label: "Hoshdar dar load-e config.yml:",
            config_warning_label: "E'lam-e config.yml:",
            cfg_warn_unknown_key: "Key-e config nashenakhte: {}",
            cfg_warn_invalid_value: "{} meghdar-e na-motabar darad, meghdar-e pishfarz estefade shod",
            cfg_warn_max_concurrent: "MAX_CONCURRENT < 1, be 50 reset shod",
            cfg_warn_ip_version: "IP_VERSION na-motabar ast, be ipv4 reset shod",
            cfg_warn_fingerprint: "TLS_FINGERPRINT '{}' nashenakhte, rustls estefade shod",
            cfg_warn_stub_threshold: "DNS_STUB_THRESHOLD kharej az baze 1..50 ast, be 2 reset shod",
            cfg_warn_upload_port: "TELEGRAM_UPLOAD_PORT na-motabar ast, be 443 reset shod",
            cfg_warn_dc_port: "TELEGRAM_DC_PORT na-motabar ast, be 443 reset shod",

            warn_unknown_lang: "Hoshdar: --lang '{}' nashenakhte (entezar: ru|en|zh|fa|auto), en estefade shod",
            warn_unknown_fingerprint: "Hoshdar: --fingerprint '{}' nashenakhte (entezar: rustls|custom|chrome|safari), {} estefade shod",
            warn_unknown_burst_axis: "Hoshdar: meghdar-e nashenakhte {} '{}', {} estefade shod",
            press_enter_to_exit: "Baraye khorooj Enter ra feshar dahid...",
            invalid_proxy_err: "Proxy-e na-motabar {}: {}\n",
            dns_servers_empty_skip: "Meghdar-e DNS_AVAILABILITY_SERVERS dar config.yml taeen nashode ast - test nadide gerefte shod.\n",
            no_sni_label: "(bedoone SNI)",
            detail_timeout_word: "Mohlat",
            detail_read_timeout: "Mohlat-e khandan",
            detail_write_timeout: "Mohlat-e neveshtan",
            detail_at: "dar",
            detail_isp_stub: "Blockpage-e ISP",
            detail_local_ip: "IP-e mahalli",
            cli_about: "Abzare sare' va kam-hafezeye tashkhis-e DPI va sansur",
            cli_help: "Namayesh-e help",
            cli_version: "Namayesh-e version",
            cli_usage_heading: "Estefade:",
            cli_usage: "dpi-detector [GOZINE HA]",
            cli_options_heading: "Gozine ha",
            cli_tests: "String-e entekhab-e test ha (mesal: '012', '1', '2')",
            cli_json: "Khorooj-e JSON (machine-readable)",
            cli_verbose: "Faal kardan-e log-e verbose/debug",
            cli_lang: "Zaban-e barname (ru, en, zh, fa, auto). Pishfarz: auto",
            cli_profile: "Profile-e mantaghe-i-e sansur (ru, ir, cn, global)",
            cli_legend: "Namayesh-e rahnemaye vaziyat ha va khorooj",
            cli_proxy: "URL-e proxy-e SOCKS5 (mesal: socks5://127.0.0.1:1080)",
            cli_concurrency: "Hadde aksar-e darkhast haye hamzaman",
            cli_domain: "Domain haye khass baraye barresi (mitavanid tekrar konid: -d vk.com -d ya.ru)",
            cli_output: "Masir-e file baraye zakhire-ye report",
            cli_burst: "Stress-e fingerprint (test 7): darkhast haye hamzaman dar har round [pishfarz: 4]",
            cli_burst_timeout: "Test 7: timeout-e yek mosafehe, sanie [pishfarz: 8]",
            cli_burst_profiles: "Fingerprint haye test 7: all|rustls,custom(firefox133),chrome(chrome107),safari(safari155) [pishfarz: all]",
            cli_burst_tls: "Version-e TLS baraye test 7: 1.2|1.3 [pishfarz: 1.3]",
            cli_burst_alpn: "ALPN baraye test 7: h2 (h2 ba bazgasht be http/1.1)|http/1.1 (faghat http/1.1) [pishfarz: h2]",
            cli_domains: "Masir-e file-e list-e domain ha",
            cli_tcp16: "Masir-e file-e target haye TCP16",
            cli_ascii: "Khorooj-e faghat ASCII baraye console haye ghadimi (bedun-e glyph ya border-e Unicode)",
            cli_fingerprint: "Profile-e fingerprint-e TLS ClientHello (rustls|custom|chrome|safari). custom = Firefox 133, chrome = Chrome 107 / Edge 99-101, safari = Safari 15.5-18.4 az curl-impersonate; hame h2 pishnahad mikonand",
        },
    }
}

/// Full diagnostic status legend as text (mirrors `cli/ui.py::print_legend`).
/// Terms stay Latin; descriptions follow the selected language (en/ru full,
/// other languages fall back to English descriptions).
///
/// Returns the text instead of printing it: the caller owns the console, and on
/// a legacy (non-VT) Windows console raw `println!` bytes land on screen as
/// `?[36m` garbage — the SGR has to go through the binary's output writer, which
/// translates it into console attributes.
pub fn legend_text(lang: Language, msg: &Messages) -> String {
    let mut out = format!("{}\n", format_bidi(msg.legend_title, lang));
    let sections = match lang {
        Language::Ru => legend_sections(),
        Language::Zh => legend_sections_zh(),
        Language::Fa => legend_sections_fa(),
        Language::En => legend_sections_en(),
    };
    for (section, items) in &sections {
        out.push_str(&format!("  {}\n", format_bidi(section, lang)));
        for (term, desc) in items {
            out.push_str(&format!(
                "    \x1b[36m{:<14}\x1b[0m \x1b[2m{}\x1b[0m\n",
                term,
                format_bidi(desc, lang)
            ));
        }
        out.push('\n');
    }
    out
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
            ("REDIR", "红色 — 重定向至外部陌生域名 (可疑)；重定向至同一主域名/子域名时显示为 OK"),
        ]),
        ("— TCP 16-20KB 测试 —", vec![
            ("DETECTED", "传输达到 14–36 KB 后连接被切断 (特征性窗口阻断)"),
            ("OK", "所有 10 次请求 (最高 40 KB) 均正常传输无阻断"),
        ]),
        ("— 其他 —", vec![
            ("OK", "站点可正常访问 (状态码 200–4xx 无阻断特征)"),
            ("UNKNOWN", "未知异常 (括号内为具体异常类型)"),
            ("TIMEOUT", "服务器接受了连接但未及时返回数据: DPI 切断/限速、丢包或服务器过载"),
            ("POOL TIMEOUT", "套接字连接池耗尽 — 请降低并发连接数"),
        ]),
    ]
}

/// Full legend in Finglish: the Persian interface is romanized (Latin letters,
/// no diacritics, "we dont use a"), technical terms and status badges stay in
/// English. Section headings and entries mirror the English legend one to one.
pub fn legend_sections_fa() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("- TLS / DPI -", vec![
            ("TLS DPI", "Tajhizat-e DPI ettesal-e TLS ra dastkari ya ghat mikonand: EOF, record-e kharab, laghv-e mosafhe"),
            ("TLS MITM", "Hamle-ye mard-e miyani: gavahi-ye ja'li (marja'-e nashenakhte, monghazi, adam-e tatabogh-e name-e mizban)"),
            ("TLS BLOCK", "Masdoodsazi-e noskhe ya kole protocol-e TLS (ekhtar-e protocol_version)"),
            ("TLS RST", "Baste-ye fa'al-e TCP RST pas az ersal-e ClientHello (reset-e mosafhe-ye TLS)"),
            ("TLS DROP", "Etmam-e mohlat-e mosafhe-ye TLS - packet ha hazf shodand"),
            ("UNKNOWN", "Khatay-e nashenakhte (no'-e khata dar parantez)"),
            ("NO TLS1.3", "Kargozar az TLS 1.3 poshtibani nemikonad (tabi'i baraye kargozar-haye ghadimi)"),
        ]),
        ("- TCP / Ettesal -", vec![
            ("TCP RST", "Ettesal reset shod (baste-ye TCP RST tavasot-e filtering ya kargozar)"),
            ("SYN DROP", "Etmam-e mohlat-e ettesal-e TCP - baste-ye SYN ersal shod vali pasokhi nayamad"),
            ("ABORT", "Ettesal laghv shod (ConnectionAborted / BrokenPipe)"),
            ("REFUSED", "Ettesal-e TCP rad shod (ECONNREFUSED)"),
            ("TIMEOUT", "Etmam-e mohlat: dur andakhtan-e SYN, mohlat-e khandan ya khatay-e system"),
            ("NET UNREACH", "Masir-e shabake dar dastras nist (ICMP unreachable)"),
            ("HOST UNREACH", "Mizban dar dastras nist"),
            ("OS ERR", "Sayer-e khata-haye system-amel (errno)"),
        ]),
        ("- DNS -", vec![
            ("DNS FAIL", "Domain az tarigh-e kargozar-e system hal nashod"),
            ("DNS FAKE", "Adres-e IP ba blockpage-e era'e-dahande motabeghat darad"),
            ("TIMEOUT", "Kargozar-e DNS dar zaman-e mogharrar pasokh nadad"),
            ("BLOCKED", "Kargozar-e DoH tavasot-e era'e-dahande masdood shode ast"),
            ("NXDOMAIN", "Be gofte-ye in kargozar, domain vojud nadarad"),
        ]),
        ("- HTTP / Masdoodsazi -", vec![
            ("BLOCKED", "Kode 451 HTTP - be dalayel-e ghanuni dar dastras nist"),
            ("ISP PAGE", "Adres-e IP-e hal shode blockpage-e era'e-dahande ast"),
            ("REDIR", "Ghermez - hedayat be domain-e bigane (mashkuk); hedayat be haman domain ya subdomain = OK"),
        ]),
        ("- Azmun-e TCP 16-20KB -", vec![
            ("DETECTED", "Ghat'-e ettesal pas az ersal-e 14 ta 36 kilobyte"),
            ("OK", "Har 10 darkhast (ta 40 kilobyte) bedun-e ghat'i anjam shodand"),
        ]),
        ("- Sayer -", vec![
            ("OK", "Site dar dastras ast (kode 200-4xx bedun-e alayem-e filtering)"),
            ("UNKNOWN", "Khatay-e nashenakhte (no'-e khata dar parantez)"),
            ("TIMEOUT", "Pasokhi az kargozar dar zaman-e mogharrar naresid: ekhtelal/kondi-ye DPI, oft-e packet ya bar-e kargozar"),
            ("POOL TIMEOUT", "Takmil-e zarfiyat-e socket ha - lotfan teedade worker ha ra kahesh dahid"),
        ]),
    ]
}

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
            ("REDIR", "Красный — редирект на чужой домен (подозрительно); редирект на тот же домен/поддомен — это OK"),
        ]),
        ("— TCP 16-20KB тест —", vec![
            ("DETECTED", "Обрыв соединения после отправки 14–36 KB"),
            ("OK", "Все 10 запросов (до 40 КБ) прошли без обрыва"),
        ]),
        ("— Прочее —", vec![
            ("OK", "Сайт доступен (200–4xx без признаков блокировки)"),
            ("UNKNOWN", "Неизвестная ошибка (в скобках — тип исключения)"),
            ("TIMEOUT", "Сервер принял запрос, но ответ не пришёл вовремя: DPI-обрыв/замедление, потеря пакетов или перегрузка сервера"),
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
            ("REDIR", "Red — redirect to a foreign domain (suspicious); a redirect to the same domain/subdomain reads as OK"),
        ]),
        ("— TCP 16-20KB test —", vec![
            ("DETECTED", "Connection break after sending 14–36 KB"),
            ("OK", "All 10 requests (up to 40 KB) passed without a break"),
        ]),
        ("— Other —", vec![
            ("OK", "Site reachable (200–4xx with no block signs)"),
            ("UNKNOWN", "Unknown error (exception type in parentheses)"),
            ("TIMEOUT", "Server accepted the request but the reply never arrived: DPI break/throttling, packet loss or server overload"),
            ("POOL TIMEOUT", "Socket pool exhausted — lower MAX_CONCURRENT"),
        ]),
    ]
}

impl Messages {
    /// Text for a recoverable configuration problem (see [`crate::config::ConfigWarning`]).
    pub fn config_warning(&self, warning: &crate::config::ConfigWarning) -> String {
        use crate::config::ConfigWarning as W;
        match warning {
            W::UnknownKey { key } => self.cfg_warn_unknown_key.replace("{}", key),
            W::InvalidValue { key } => self.cfg_warn_invalid_value.replace("{}", key),
            W::UnknownFingerprint { value } => self.cfg_warn_fingerprint.replace("{}", value),
            W::MaxConcurrentReset => self.cfg_warn_max_concurrent.to_string(),
            W::IpVersionReset => self.cfg_warn_ip_version.to_string(),
            W::StubThresholdReset => self.cfg_warn_stub_threshold.to_string(),
            W::UploadPortReset => self.cfg_warn_upload_port.to_string(),
            W::DcPortReset => self.cfg_warn_dc_port.to_string(),
        }
    }
}

/// Display label for a TLS ClientHello profile. The canonical token and the
/// profile names stay Latin (rule 4); only the default profile is spelled out
/// per language ("pishfarz" is the Finglish for "default").
pub fn fingerprint_label(fp: crate::net::fingerprint::TlsFingerprint, lang: Language) -> &'static str {
    use crate::net::fingerprint::TlsFingerprint as F;
    match (fp, lang) {
        (F::Rustls, Language::Fa) => "rustls (pishfarz)",
        (F::Rustls, _) => "rustls (default)",
        (F::Custom, _) => "firefox 133",
        (F::Chrome, _) => "curl chrome 107",
        (F::Safari, _) => "curl safari 155",
    }
}

/// Transfer rate in the interface's speed units (Ru uses Cyrillic units).
pub fn fmt_speed(bps: f64, lang: Language) -> String {
    let msg = get_messages(lang);
    if bps >= 1024.0 * 1024.0 {
        format!("{:>6.2} {}", bps / (1024.0 * 1024.0), msg.unit_mb_s)
    } else if bps >= 1024.0 {
        format!("{:>6.1} {}", bps / 1024.0, msg.unit_kb_s)
    } else {
        format!("{:>6.0} {}", bps, msg.unit_b_s)
    }
}

/// Byte count in the interface's size units.
pub fn fmt_size(bytes: u64, lang: Language) -> String {
    let msg = get_messages(lang);
    if bytes >= 1024 * 1024 {
        format!("{:.2} {}", bytes as f64 / (1024.0 * 1024.0), msg.unit_mb)
    } else if bytes >= 1024 {
        format!("{:.1} {}", bytes as f64 / 1024.0, msg.unit_kb)
    } else {
        format!("{} {}", bytes, msg.unit_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_parsing() {
        assert_eq!(Language::from_code("ru"), Some(Language::Ru));
        assert_eq!(Language::from_code("en"), Some(Language::En));
        assert_eq!(Language::from_code("zh"), Some(Language::Zh));
        assert_eq!(Language::from_code("fa"), Some(Language::Fa));
        assert_eq!(Language::from_code("unknown"), None);
    }

    /// The live progress line must name what it is counting. Test 1 is labelled
    /// with the block tokens UDP/DoH/DoT/EGRESS, so it needs no wording of its
    /// own; the TCP window test names itself instead of a generic "Checking...".
    #[test]
    fn test_phase_text_names_each_phase() {
        for lang in [Language::En, Language::Ru, Language::Zh, Language::Fa] {
            let msg = get_messages(lang);
            assert_eq!(msg.phase_text(crate::PhaseId::DnsAvailability), "DNS");
        }
        assert_eq!(
            get_messages(Language::En).phase_text(crate::PhaseId::Tcp16),
            "TCP 16–20 KB Block Check"
        );

        // Tokens are canonical Latin across every language (rule 4).
        assert_eq!(crate::ProgressBlock::Udp.token(), "UDP");
        assert_eq!(crate::ProgressBlock::Doh.token(), "DoH");
        assert_eq!(crate::ProgressBlock::Dot.token(), "DoT");
        assert_eq!(crate::ProgressBlock::Egress.token(), "EGRESS");
    }

    #[test]
    fn test_messages_coverage() {
        for lang in [
            Language::En,
            Language::Ru,
            Language::Zh,
            Language::Fa,
        ] {
            let msg = get_messages(lang);
            assert!(!msg.banner_subtitle.is_empty());
            assert!(!msg.dns_title.is_empty());
            assert!(!msg.domain_title.is_empty());
            assert!(!msg.update_failed.is_empty());
            assert!(!msg.proxy_in_use.is_empty());
            assert!(!msg.tui_unavailable.is_empty());
            assert!(!msg.crash_title.is_empty());
            assert!(!msg.detail_read_timeout.is_empty());
            assert!(!msg.cli_about.is_empty());
            assert!(!msg.cfg_warn_invalid_value.is_empty());
            assert!(!msg.cfg_warn_unknown_key.is_empty());
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

    /// Finglish is written with Latin letters: no Persian/Arabic script and no
    /// Latin diacritics (the reviewer's rule - "we dont use a with accent").
    /// The only non-ASCII characters allowed are the status marks every other
    /// language uses in the same places.
    #[test]
    fn test_finglish_is_latin_only() {
        const MARKS: [char; 4] = ['✓', '×', '⚠', '↑'];
        let mut texts = vec![format!("{:?}", get_messages(Language::Fa))];
        for (section, entries) in legend_sections_fa() {
            texts.push(section.to_string());
            for (term, desc) in entries {
                texts.push(term.to_string());
                texts.push(desc.to_string());
            }
        }
        for text in texts {
            for (i, c) in text.char_indices() {
                if c.is_ascii() || MARKS.contains(&c) {
                    continue;
                }
                let from = text[..i].char_indices().rev().nth(39).map(|(k, _)| k).unwrap_or(0);
                panic!(
                    "Finglish must be Latin: {:?} (U+{:04X}) in ...{}...",
                    c,
                    c as u32,
                    &text[from..i + c.len_utf8()]
                );
            }
        }
    }
}
