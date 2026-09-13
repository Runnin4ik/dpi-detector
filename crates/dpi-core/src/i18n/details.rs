//! Human text for the canonical diagnostic details emitted by
//! [`crate::classify`] and the probe layer.
//!
//! Details are identifiers, not prose: classification compares them
//! (`is_detected`, whitelist ban detection) and `--json` emits them verbatim.
//! They are therefore never rewritten in place — this module is the single
//! place that turns them into display text. Russian is the source language of
//! the canonical strings, so the Russian interface passes them through as is.

use super::{get_messages, Language};
use crate::classify::*;

fn t(lang: Language, en: &str, zh: &str, fa: &str) -> String {
    match lang {
        Language::Zh => zh,
        Language::Fa => fa,
        _ => en,
    }
    .to_string()
}

/// Translates a single-line detail. Unknown details pass through unchanged.
pub fn detail_text(detail: &str, lang: Language) -> String {
    if lang == Language::Ru {
        return detail.to_string();
    }
    let msg = get_messages(lang);
    if let Some(text) = known(detail, lang) {
        return text;
    }
    // Offset details: "<head> at <n>KB", where the head is itself a detail.
    if let Some((head, tail)) = detail.split_once(DET_AT_KB_MARKER) {
        if tail.ends_with(DET_KB_SUFFIX) {
            return format!("{} {} {}", detail_text(head, lang), msg.detail_at, tail);
        }
    }
    // "<word> (<stage>)" — the stage stays a Latin token.
    if let Some(rest) = detail.strip_prefix(DET_TIMEOUT_WORD) {
        if let Some(stage) = rest.strip_prefix(" (").and_then(|r| r.strip_suffix(')')) {
            return format!("{} ({})", msg.detail_timeout_word, stage);
        }
    }
    // "<word> <n>KB" — the number and unit stay as they are.
    for word in [
        DET_TIMEOUT_WORD,
        DET_READ_TIMEOUT_WORD,
        DET_READ_TIMEOUT_WORD_CAPS,
        DET_WRITE_TIMEOUT_WORD,
    ] {
        if let Some(rest) = detail.strip_prefix(word) {
            if let Some(n) = rest.strip_suffix(DET_KB_SUFFIX) {
                return format!("{} {}KB", detail_text(word, lang), n.trim());
            }
        }
    }
    if let Some(rest) = detail.strip_prefix(DET_ISP_STUB_ARROW) {
        return format!("{} -> {}", msg.detail_isp_stub, rest);
    }
    if let Some(rest) = detail.strip_prefix(DET_ISP_STUB_SPACE) {
        return format!("{} {}", msg.detail_isp_stub, rest);
    }
    if let Some(rest) = detail.strip_prefix(DET_LOCAL_IP_ARROW) {
        return format!("{} -> {}", msg.detail_local_ip, rest);
    }
    detail.to_string()
}

/// Translates `proto: detail` lines (one per line, as stored in a domain row).
pub fn detail_lines(raw: &str, lang: Language) -> String {
    if lang == Language::Ru {
        return raw.to_string();
    }
    raw.lines()
        .map(|line| match line.split_once(':') {
            Some((proto, rest)) => format!("{}:{}", proto, detail_text(rest, lang)),
            None => detail_text(line, lang),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn known(detail: &str, lang: Language) -> Option<String> {
    let text = match detail {
        DET_RST_HELLO | DET_STREAM_RST_HELLO => {
            t(lang, "TCP RST on ClientHello", "ClientHello 上的 TCP RST", "TCP RST roye ClientHello")
        }
        DET_STREAM_EOF_HELLO => t(
            lang,
            "DPI closed the connection right after TLS ClientHello",
            "DPI 在 TLS ClientHello 之后立即关闭连接",
            "DPI ettesal ra fauran pas az TLS ClientHello bast",
        ),
        DET_STREAM_RST_CONNECT => t(
            lang,
            "TCP RST received from DPI on connect",
            "连接时收到 DPI 发送的 TCP RST",
            "TCP RST az taraf-e DPI dar zaman-e ettesal",
        ),
        DET_TLS_DROP_HANDSHAKE => t(
            lang,
            "TLS DROP (connection dropped during TLS handshake)",
            "TLS DROP（TLS 握手期间连接被丢弃）",
            "TLS DROP (ettesal dar zaman-e TLS handshake ghat shod)",
        ),
        DET_TIMEOUT_CONN => t(lang, "TIMEOUT (connection timeout)", "TIMEOUT（连接超时）", "TIMEOUT (mohlat-e ettesal)"),
        DET_TLS_RST_HELLO => t(
            lang,
            "TLS RST (connection reset after ClientHello)",
            "TLS RST（ClientHello 之后连接被重置）",
            "TLS RST (ettesal pas az ClientHello reset shod)",
        ),
        DET_WRONG_VERSION => t(
            lang,
            "Response spoofing (Wrong Version)",
            "响应伪造（Wrong Version）",
            "Spoofing-e pasokh (Wrong Version)",
        ),
        DET_GARBAGE_DATA => t(
            lang,
            "Response spoofing (Garbage Data)",
            "响应伪造（Garbage Data）",
            "Spoofing-e pasokh (Garbage Data)",
        ),
        DET_SNI_BLOCK_UNREC => t(
            lang,
            "SNI block (unrecognized name)",
            "SNI 封锁（unrecognized name）",
            "Block-e SNI (unrecognized name)",
        ),
        DET_DPI_ALERT_HS_FAIL => t(
            lang,
            "DPI alert (handshake failure)",
            "DPI 警报（handshake failure）",
            "Alert-e DPI (handshake failure)",
        ),
        DET_PROTOCOL_VERSION_ALERT => {
            t(lang, "Protocol version alert", "协议版本警报", "Alert-e version-e protocol")
        }
        DET_FAKE_TLS_ALERT => t(lang, "Fake TLS alert", "伪造的 TLS 警报", "Alert-e TLS-e ja'li"),
        DET_NO_ROOT_CA => t(lang, "Missing root certificates", "缺少根证书", "Certificate haye rishe vojud nadarad"),
        DET_CERT_EXPIRED => t(lang, "Certificate expired", "证书已过期", "Certificate monghazi shode ast"),
        DET_SELF_SIGNED => t(lang, "Self-signed certificate", "自签名证书", "Certificate-e self-signed"),
        DET_HOSTNAME_MISMATCH => t(lang, "Hostname mismatch", "主机名不匹配", "Adam-e tatabogh-e hostname"),
        DET_FAKE_CERT => t(lang, "Certificate spoofing", "证书伪造", "Spoofing-e certificate"),
        DET_TRANSFER_EOF => t(lang, "Transfer EOF", "传输中断 (EOF)", "Ghat'-e enteghal (EOF)"),
        DET_HANDSHAKE_EOF => t(lang, "Quiet teardown (handshake EOF)", "静默中断（handshake EOF）", "Ghat'-e khamush (handshake EOF)"),
        DET_NO_TLS13 => t(
            lang,
            "Server has no TLS 1.3",
            "服务器不支持 TLS 1.3",
            "Server az TLS 1.3 poshtibani nemikonad",
        ),
        DET_POOL_TIMEOUT => t(lang, "Socket pool exhausted", "套接字池耗尽", "Socket pool por shod"),
        DET_TLS_HANDSHAKE_TIMEOUT => t(lang, "TLS handshake timeout", "TLS 握手超时", "Mohlat-e TLS handshake"),
        DET_TCP_SYN_TIMEOUT => t(lang, "TCP SYN timeout", "TCP SYN 超时", "Mohlat-e TCP SYN"),
        DET_SEND_TIMEOUT => t(lang, "Send timeout", "发送超时", "Mohlat-e ersal"),
        DET_SYN_TIMEOUT_SHORT => t(lang, "SYN timeout", "SYN 超时", "Mohlat-e SYN"),
        DET_READ_TIMEOUT | DET_READ_TIMEOUT_WORD | DET_READ_TIMEOUT_WORD_CAPS => {
            t(lang, "Read timeout", "读取超时", "Mohlat-e khandan")
        }
        DET_WRITE_TIMEOUT_WORD => t(lang, "Write timeout", "写入超时", "Mohlat-e neveshtan"),
        DET_TIMEOUT_WORD => t(lang, "Timeout", "超时", "Mohlat"),
        DET_ALERT_HANDSHAKE => t(lang, "Handshake alert", "握手警报", "Alert-e handshake"),
        DET_ALERT_SNI => t(lang, "SNI alert", "SNI 警报", "Alert-e SNI"),
        DET_ALERT_VERSION => t(lang, "Version alert", "版本警报", "Alert-e version"),
        DET_ALERT_TLS => t(lang, "TLS alert", "TLS 警报", "Alert-e TLS"),
        DET_UNKNOWN_CONN_FAILURE => {
            t(lang, "Unknown connection failure", "未知连接错误", "Khata-ye nashenakhte dar ettesal")
        }
        DET_DOMAIN_NOT_FOUND => t(lang, "Domain not found", "域名未找到", "Domain peyda nashod"),
        DET_DNS_TIMEOUT_UNAVAIL => t(lang, "DNS timeout/unavailable", "DNS 超时/不可用", "DNS mohlat ya dar dastras nist"),
        DET_DNS_ERROR => t(lang, "DNS error", "DNS 错误", "Khata-ye DNS"),
        DET_CONN_REFUSED => t(lang, "TCP connection refused", "TCP 连接被拒绝", "Ettesal-e TCP rad shod"),
        DET_RST_AFTER_HANDSHAKE => t(lang, "TCP RST after handshake", "握手后的 TCP RST", "TCP RST ba'd az handshake"),
        DET_CONN_RESET => t(lang, "TCP connection reset", "TCP 连接被重置", "Ettesal-e TCP reset shod"),
        DET_ABORTED | DET_TCP_ABORTED => t(lang, "Connection aborted", "连接被中止", "Ettesal laghv shod"),
        DET_NET_UNREACH => t(lang, "Net unreachable", "网络不可达", "Shabake dar dastras nist"),
        DET_HOST_UNREACH => t(lang, "Host unreachable", "主机不可达", "Mizban dar dastras nist"),
        DET_IPV6_UNSUPPORTED => t(
            lang,
            "IPv6 not supported/disabled",
            "IPv6 不受支持或已禁用",
            "IPv6 poshtibani nemishavad ya ghayr-e fa'al ast",
        ),
        DET_IPV6_NOT_SUPPORTED_SHORT => t(lang, "IPv6 not supported", "IPv6 不受支持", "IPv6 poshtibani nemishavad"),
        _ => return None,
    };
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Language::*;

    #[test]
    fn russian_passes_through_untouched() {
        for detail in ALL_DET_DETAILS {
            assert_eq!(&detail_text(detail, Ru), detail);
        }
        assert_eq!(detail_text("Timeout at 24KB", Ru), "Timeout at 24KB");
    }

    #[test]
    fn every_canonical_detail_is_translated_for_zh_and_fa() {
        for detail in ALL_DET_DETAILS {
            for lang in [En, Zh, Fa] {
                let out = detail_text(detail, lang);
                assert!(!out.is_empty(), "{detail} [{lang:?}]");
                if lang != En {
                    assert_ne!(out, *detail, "{detail} has no {lang:?} translation");
                }
            }
        }
    }

    #[test]
    fn composed_details_keep_their_tokens() {
        assert_eq!(detail_text("Timeout (reading_data)", Zh), "超时 (reading_data)");
        assert_eq!(detail_text("Timeout (reading_data)", Fa), "Mohlat (reading_data)");
        assert_eq!(detail_text("Timeout 20.0KB", Zh), "超时 20.0KB");
        assert_eq!(detail_text("Read Timeout at 24KB", Zh), "读取超时 在 24KB");
        assert_eq!(detail_text("Read timeout 8.0KB", Fa), "Mohlat-e khandan 8.0KB");
        assert_eq!(detail_text(&format!("{}{}", DET_ISP_STUB_ARROW, "1.1.1.1"), En), "ISP blockpage -> 1.1.1.1");
        assert_eq!(detail_text(&format!("{}{}", DET_LOCAL_IP_ARROW, "10.0.0.1"), Zh), "本地 IP -> 10.0.0.1");
        assert_eq!(detail_text("HTTP 451", Zh), "HTTP 451");
        assert_eq!(detail_text("→ https", En), "→ https");
    }

    #[test]
    fn domain_detail_lines_translate_after_the_protocol() {
        let raw = "TLS1.3:Timeout at 24KB\nTLS1.2:OK";
        assert_eq!(detail_lines(raw, En), "TLS1.3:Timeout at 24KB\nTLS1.2:OK");
        assert_eq!(detail_lines(raw, Zh), "TLS1.3:超时 在 24KB\nTLS1.2:OK");
        assert_eq!(detail_lines(raw, Ru), raw);
    }
}
