//! Finglish interface text: the [`Messages`] literal and the status legend.

use super::{Language, Messages};

pub(crate) fn messages() -> Messages {
    Messages {
        netinfo_title: "Ettela'ate shabake va system",
        domain_title: "Natayej-e barresi-e domain ha (TLS / SNI):",
        summary_title: "Kholase-ye natayej",
        status: "Vaziyat",
        available: "AVAILABLE",
        blocked: "BLOCKED",
        domain: "Domain",
        detail: "Joz'iyat",
        provider: "Ara'e-dahande",
        region: "Mantaghe",
        menu_title: "Tanzimat va entekhab-e test ha",
        menu_language: "Zaban",
        menu_ip_version: "IP version",
        menu_concurrency: "Teedade worker ha",
        menu_hw_row: "Peymayesh",
        menu_hw_change: "Taghir",
        menu_hw_tests: "Test ha",
        menu_hw_start: "Shoroo",
        menu_hw_quit: "Khorooj",
        menu_need_one: "Hadaghal yek test ra entekhab konid",
        menu_test_netinfo: "Ettela'ate shabake va system",
        menu_test_dns: "DNS server haye dar dastras",
        menu_test_domains: "Website haye dar dastras",
        menu_test_tcp: "CDN va hosting haye dar dastras",
        menu_test_sni: "Jost o juye SNI haye whitelist",
        menu_test_telegram: "Dastrasi be Telegram",
        menu_test_legend: "Rahnemaye barname",
        menu_test_burst: "Fingerprint/Sibir blocking",
        burst_settings_title: "Tanzimat-e test 6",
        burst_field_attempts: "Darkhast be har host",
        burst_field_timeout: "Timeout be sanie",
        burst_field_domain: "Domain baraye test",
        burst_domain_placeholder: "Baraye neveshtan -> bezanid",
        burst_domain_default_hint: "Pishfarz - hame-ye domain ha",
        burst_field_tls: "Version-e TLS",
        burst_field_http: "Protocol-e HTTP",
        burst_field_profiles: "Fingerprint",
        burst_profiles_all: "hame",
        burst_testing: "Dar hal-e test",
        fingerprint_label: "Fingerprint",
        fingerprint_note: "Har profile yek shape-e pin-shode-ye curl-impersonate ra bazsazi mikonad: FIREFOX = firefox133, CHROME = chrome107 (va edge 99-101), SAFARI = safari155. Hame h2 va http/1.1 ra mesl-e browser ha pishnahad mikonand. Hich yek copy-e byte-be-byte-e yek browser-e vaghe-i nist - fingerprinting-e amigh-tar (HTTP/2 settings, record timing) hanuz mitavanad anha ra tafzil konad.",
        lang: Language::Fa,
        replies_label: "pasokh ha",
        blocked_short: "masdood",
        mixed_short: "tarkibi",
        legend_title: "\nRahnemaye vaziyat ha:\n",
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

        intercept_excluded: "nfqws2 ejra mishavad, amma traffic-e detector ra nemibinad:\n\
                             ettefasl tavasot-e policy-e dastresi \"{}\" mostasna shod.\n\n\
                             Baraye inke obur be khode router ham ezafe shavad, movaqqatan POLICY_EXCLUDE=1\n\
                             ra bezarid ya POLICY_NAME ra be esmi ke vojood nadarad taghir dahid, sepas:",
        intercept_excluded_unnamed: "nfqws2 ejra mishavad, amma traffic-e detector ra nemibinad:\n\
                                     ettefasl tavasot-e policy-e dastresi mostasna shod.\n\n\
                                     Baraye inke obur be khode router ham ezafe shavad, movaqqatan POLICY_EXCLUDE=1\n\
                                     ra bezarid ya POLICY_NAME ra be esmi ke vojood nadarad taghir dahid, sepas:",
        intercept_interface: "nfqws2 ejra mishavad, amma traffic-e detector ra nemibinad:\n\
                              qavanin rooy-e interface-e {} ast, amma traffic-e ma az {} miravad.\n\n\
                              Baraye inke obur traffic-e ma ra ham begirad, in interface ra be ISP_INTERFACE\n\
                              ezafe konid (/opt/etc/nfqws2/nfqws2.conf, chand tai ba fasele), sepas:",
        intercept_ports: "nfqws2 ejra mishavad, amma traffic-e detector ra nemibinad:\n\
                          porti ke ma estefade mikonim ra pardazesh nemikonad.\n\n\
                          Port ra be TCP_PORTS va be --filter-tcp-e strategy ezafe konid, sepas:",
        intercept_ipv6: "nfqws2 ejra mishavad, amma traffic-e detector ra nemibinad:\n\
                         qavanin-e IPv6 nasb nemishavand - dar config IPV6_ENABLED=0 ast.\n\n\
                         Baraye inke obur rooy-e IPv6 ham kar konad, IPV6_ENABLED=1\n\
                         ra dar /opt/etc/nfqws2/nfqws2.conf bezarid, sepas:",
        intercept_unchecked: "nfqws2 ejra mishavad, amma queue javab nemidahad - barresi nashod.\n\
                              Ehtemalan service hanuz bala nayamade, an ra restart konid:",

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
        warn_unknown_fingerprint: "Hoshdar: --fingerprint '{}' nashenakhte (entezar: rustls|firefox|chrome|safari), {} estefade shod",
        warn_unknown_burst_axis: "Hoshdar: meghdar-e nashenakhte {} '{}', {} estefade shod",
        press_enter_to_exit: "Baraye khorooj Enter ra feshar dahid...",
        invalid_proxy_err: "Proxy-e na-motabar {}: {}\n",
        dns_servers_empty_skip: "Meghdar-e DNS_AVAILABILITY_SERVERS dar config.yml taeen nashode ast - test nadide gerefte shod.\n",
        no_sni_label: "(bedoone SNI)",
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
        cli_burst: "Fingerprint/Sibir blocking (test 6): darkhast be har host, ba ta'khir-e 20 ms [pishfarz: 5]",
        cli_burst_timeout: "Test 6: timeout-e mosafehe, sanie [pishfarz: 8]; darkhast-e baad az aan montazer-e read_timeout mimanad",
        cli_burst_profiles: "Fingerprint haye test 6: all|rustls,firefox(firefox133),chrome(chrome107),safari(safari155) [pishfarz: all]",
        cli_burst_tls: "TLS baraye test 6: 1.3+1.2 (pishnahad-e browser, pasokh bayad 1.3 bashad)|1.3 (faghat 1.3)|1.2 (faghat 1.2) [pishfarz: 1.3+1.2]",
        cli_burst_alpn: "ALPN baraye test 6: h2 (h2 ba bazgasht be http/1.1)|http/1.1 (faghat http/1.1) [pishfarz: h2]",
        cli_trace: "Trace baraye test 6: yek khat baraye har talash (dore, fingerPrint, domain, vaziyat, joz'yat, ms); bedun-e masir be stderr, ba masir be an file [pishfarz: khamush]",
        trace_open_failed: "File-e trace baz nashod {}",
        cli_domains: "Masir-e file-e list-e domain ha",
        cli_tcp16: "Masir-e file-e target haye TCP16",
        cli_ascii: "Khorooj-e faghat ASCII baraye console haye ghadimi (bedun-e glyph ya border-e Unicode)",
        cli_fingerprint: "Profile-e fingerprint (rustls|firefox|chrome|safari): ClientHello, User-Agent va header ha, moqaddame-e HTTP/2. firefox = Firefox 133, chrome = Chrome 107 / Edge 99-101, safari = Safari 15.5-18.4 az curl-impersonate; hame h2 pishnahad mikonand",
    }
}

/// Full legend in Finglish: the Persian interface is romanized (Latin letters,
/// no diacritics, "we dont use a"), technical terms and status badges stay in
/// English. Section headings and entries mirror the English legend one to one.
pub(crate) fn legend_sections_fa() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Finglish is written with Latin letters: no Persian/Arabic script and no
    /// Latin diacritics (the reviewer's rule - "we dont use a with accent").
    /// The only non-ASCII characters allowed are the status marks every other
    /// language uses in the same places.
    #[test]
    fn test_finglish_is_latin_only() {
        const MARKS: [char; 4] = ['✓', '×', '⚠', '↑'];
        let mut texts = vec![format!("{:?}", messages())];
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
