//! Human text for the diagnostic details the engine reports.
//!
//! [`Detail`] is a value, so this is an exhaustive `match`: a new variant does
//! not compile until every language has its wording. Russian is the source
//! language of the canonical strings, so the `Ru` column spells out what used to
//! be the canonical `DET_*` string. Protocol tokens inside a detail
//! (`ClientHello`, `TLS`, `SNI`, `KB`) stay Latin in every language (Rule 4).

use super::{get_messages, Language};
use dpi_core::classify::detail::{kb_display, Detail};

/// The same wording in four languages: `ru` is the canonical Russian text.
fn t4(lang: Language, ru: &str, en: &str, zh: &str, fa: &str) -> String {
    match lang {
        Language::Ru => ru,
        Language::Zh => zh,
        Language::Fa => fa,
        Language::En => en,
    }
    .to_string()
}

/// Display text of one detail, in `lang`.
pub fn detail_text(detail: &Detail, lang: Language) -> String {
    let msg = get_messages(lang);
    match detail {
        Detail::None => String::new(),
        Detail::RstHello => t4(lang, "TCP RST на ClientHello", "TCP RST on ClientHello", "ClientHello 上的 TCP RST", "TCP RST roye ClientHello"),
        Detail::StreamEofHello => t4(lang, "DPI closed connection immediately after TLS ClientHello", "DPI closed the connection right after TLS ClientHello", "DPI 在 TLS ClientHello 之后立即关闭连接", "DPI ettesal ra fauran pas az TLS ClientHello bast"),
        Detail::StreamRstConnect => t4(lang, "TCP RST received from DPI on connect", "TCP RST received from DPI on connect", "连接时收到 DPI 发送的 TCP RST", "TCP RST az taraf-e DPI dar zaman-e ettesal"),
        Detail::TlsDropHandshake => t4(lang, "TLS DROP (ТСПУ дропнул соединение при TLS handshake)", "TLS DROP (connection dropped during TLS handshake)", "TLS DROP（TLS 握手期间连接被丢弃）", "TLS DROP (ettesal dar zaman-e TLS handshake ghat shod)"),
        Detail::TimeoutConn => t4(lang, "TIMEOUT (Таймаут соединения)", "TIMEOUT (connection timeout)", "TIMEOUT（连接超时）", "TIMEOUT (mohlat-e ettesal)"),
        Detail::TlsRstHello => t4(lang, "TLS RST (ТСПУ разорвал TLS после ClientHello)", "TLS RST (connection reset after ClientHello)", "TLS RST（ClientHello 之后连接被重置）", "TLS RST (ettesal pas az ClientHello reset shod)"),
        Detail::WrongVersion => t4(lang, "Подмена ответа (Wrong Version)", "Response spoofing (Wrong Version)", "响应伪造（Wrong Version）", "Spoofing-e pasokh (Wrong Version)"),
        Detail::GarbageData => t4(lang, "Подмена ответа (Garbage Data)", "Response spoofing (Garbage Data)", "响应伪造（Garbage Data）", "Spoofing-e pasokh (Garbage Data)"),
        Detail::SniBlockUnrecognizedName => t4(lang, "SNI Block (Unrecognized Name)", "SNI block (unrecognized name)", "SNI 封锁（unrecognized name）", "Block-e SNI (unrecognized name)"),
        Detail::DpiAlertHandshakeFailure => t4(lang, "DPI Alert (Handshake Failure)", "DPI alert (handshake failure)", "DPI 警报（handshake failure）", "Alert-e DPI (handshake failure)"),
        Detail::ProtocolVersionAlert => t4(lang, "Protocol Version Alert", "Protocol version alert", "协议版本警报", "Alert-e version-e protocol"),
        Detail::FakeTlsAlert => t4(lang, "Поддельный TLS Alert", "Fake TLS alert", "伪造的 TLS 警报", "Alert-e TLS-e ja'li"),
        Detail::NoRootCa => t4(lang, "Отсутствуют корневые сертификаты", "Missing root certificates", "缺少根证书", "Certificate haye rishe vojud nadarad"),
        Detail::CertExpired => t4(lang, "Cert expired", "Certificate expired", "证书已过期", "Certificate monghazi shode ast"),
        Detail::SelfSigned => t4(lang, "Self-signed cert", "Self-signed certificate", "自签名证书", "Certificate-e self-signed"),
        Detail::HostnameMismatch => t4(lang, "Hostname mismatch", "Hostname mismatch", "主机名不匹配", "Adam-e tatabogh-e hostname"),
        Detail::FakeCert => t4(lang, "Подмена сертификата", "Certificate spoofing", "证书伪造", "Spoofing-e certificate"),
        Detail::TransferEof => t4(lang, "Обрыв при передаче (EOF)", "Transfer EOF", "传输中断 (EOF)", "Ghat'-e enteghal (EOF)"),
        Detail::HandshakeEof => t4(lang, "Тихий обрыв (Handshake EOF)", "Quiet teardown (handshake EOF)", "静默中断（handshake EOF）", "Ghat'-e khamush (handshake EOF)"),
        Detail::NoTls13 => t4(lang, "Server has no TLS 1.3", "Server has no TLS 1.3", "服务器不支持 TLS 1.3", "Server az TLS 1.3 poshtibani nemikonad"),
        Detail::PoolTimeout => t4(lang, "Нехватка сокетов, снизьте параллелизм", "Socket pool exhausted", "套接字池耗尽", "Socket pool por shod"),
        Detail::TlsHandshakeTimeout => t4(lang, "TLS Handshake timeout", "TLS handshake timeout", "TLS 握手超时", "Mohlat-e TLS handshake"),
        Detail::TcpSynTimeout => t4(lang, "TCP SYN timeout", "TCP SYN timeout", "TCP SYN 超时", "Mohlat-e TCP SYN"),
        Detail::SynTimeoutShort => t4(lang, "SYN timeout", "SYN timeout", "SYN 超时", "Mohlat-e SYN"),
        Detail::SendTimeout => t4(lang, "Таймаут отправки данных", "Send timeout", "发送超时", "Mohlat-e ersal"),
        Detail::ReadTimeout => t4(lang, "Таймаут чтения данных", "Read timeout", "读取超时", "Mohlat-e khandan"),
        Detail::TimeoutWord => t4(lang, "Timeout", "Timeout", "超时", "Mohlat"),
        Detail::ReadTimeoutWord => t4(lang, "Read timeout", "Read timeout", "读取超时", "Mohlat-e khandan"),
        Detail::ReadTimeoutWordCaps => t4(lang, "Read Timeout", "Read timeout", "读取超时", "Mohlat-e khandan"),
        Detail::WriteTimeoutWord => t4(lang, "Write Timeout", "Write timeout", "写入超时", "Mohlat-e neveshtan"),
        Detail::AlertHandshake => t4(lang, "Handshake alert", "Handshake alert", "握手警报", "Alert-e handshake"),
        Detail::AlertSni => t4(lang, "SNI alert", "SNI alert", "SNI 警报", "Alert-e SNI"),
        Detail::AlertVersion => t4(lang, "Version alert", "Version alert", "版本警报", "Alert-e version"),
        Detail::AlertTls => t4(lang, "TLS alert", "TLS alert", "TLS 警报", "Alert-e TLS"),
        Detail::UnknownConnectionFailure => t4(lang, "Unknown connection failure", "Unknown connection failure", "未知连接错误", "Khata-ye nashenakhte dar ettesal"),
        Detail::DomainNotFound => t4(lang, "Домен не найден", "Domain not found", "域名未找到", "Domain peyda nashod"),
        Detail::DnsTimeoutUnavailable => t4(lang, "DNS таймаут/недоступен", "DNS timeout/unavailable", "DNS 超时/不可用", "DNS mohlat ya dar dastras nist"),
        Detail::DnsError => t4(lang, "Ошибка DNS", "DNS error", "DNS 错误", "Khata-ye DNS"),
        Detail::ConnRefused => t4(lang, "TCP соединение отклонено", "TCP connection refused", "TCP 连接被拒绝", "Ettesal-e TCP rad shod"),
        Detail::RstAfterHandshake => t4(lang, "TCP RST после handshake", "TCP RST after handshake", "握手后的 TCP RST", "TCP RST ba'd az handshake"),
        Detail::ConnReset => t4(lang, "TCP соединение сброшено", "TCP connection reset", "TCP 连接被重置", "Ettesal-e TCP reset shod"),
        Detail::Aborted => t4(lang, "Соединение прервано (Abort)", "Connection aborted", "连接被中止", "Ettesal laghv shod"),
        Detail::TcpAborted => t4(lang, "TCP соединение прервано", "Connection aborted", "连接被中止", "Ettesal laghv shod"),
        Detail::NetUnreach => t4(lang, "Нет маршрута (ICMP unreach)", "Net unreachable", "网络不可达", "Shabake dar dastras nist"),
        Detail::HostUnreach => t4(lang, "Нет маршрута до хоста", "Host unreachable", "主机不可达", "Mizban dar dastras nist"),
        Detail::Ipv6Unsupported => t4(lang, "IPv6 не поддерживается/отключён", "IPv6 not supported/disabled", "IPv6 不受支持或已禁用", "IPv6 poshtibani nemishavad ya ghayr-e fa'al ast"),
        Detail::Ipv6NotSupportedShort => t4(lang, "IPv6 не поддерживается", "IPv6 not supported", "IPv6 不受支持", "IPv6 poshtibani nemishavad"),
        // Composed: the head is itself a detail, the offset keeps its unit.
        Detail::AtKb { head, kb } => {
            format!("{} {} {}", detail_text(head, lang), msg.detail_at, kb_display(*kb))
        }
        Detail::Kb { head, kb } => format!("{} {}", detail_text(head, lang), kb_display(*kb)),
        // The stage stays a protocol token.
        Detail::TimeoutStage { stage } => {
            format!("{} ({})", detail_text(&Detail::TimeoutWord, lang), stage)
        }
        Detail::IspBlockpage { arrow: true, ip } => format!("{} -> {}", msg.detail_isp_stub, ip),
        Detail::IspBlockpage { arrow: false, ip } => format!("{} {}", msg.detail_isp_stub, ip),
        Detail::LocalIp { ip } => format!("{} -> {}", msg.detail_local_ip, ip),
        Detail::HttpStatus(code) => format!("HTTP {}", code),
        Detail::Elapsed(secs) => format!("{:.1}s", secs),
        // Free text from the OS or the TLS stack: appended as it came.
        Detail::Other(text) => text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Language::*;

    #[test]
    fn composed_details_keep_their_tokens() {
        let stage = Detail::TimeoutStage { stage: "reading_data".into() };
        assert_eq!(detail_text(&stage, Zh), "超时 (reading_data)");
        assert_eq!(detail_text(&stage, Fa), "Mohlat (reading_data)");
        assert_eq!(detail_text(&Detail::Kb { head: Box::new(Detail::TimeoutWord), kb: 20.0 }, Zh), "超时 20KB");
        let at = Detail::at_kb(Detail::ReadTimeoutWordCaps, 24.0);
        assert_eq!(detail_text(&at, Zh), "读取超时 在 24KB");
        assert_eq!(
            detail_text(&Detail::Kb { head: Box::new(Detail::ReadTimeoutWord), kb: 8.0 }, Fa),
            "Mohlat-e khandan 8KB"
        );
        let stub = Detail::IspBlockpage { arrow: true, ip: "1.1.1.1".into() };
        assert_eq!(detail_text(&stub, En), "ISP blockpage -> 1.1.1.1");
        assert_eq!(detail_text(&Detail::LocalIp { ip: "10.0.0.1".into() }, Zh), "本地 IP -> 10.0.0.1");
        assert_eq!(detail_text(&Detail::HttpStatus(451), Zh), "HTTP 451");
        assert_eq!(detail_text(&Detail::Elapsed(0.3), Ru), "0.3s");
        assert_eq!(detail_text(&Detail::None, Ru), "");
        assert_eq!(detail_text(&Detail::Other("→ https".into()), En), "→ https");
    }

    /// Rule 4: the protocol tokens inside a detail never change language.
    #[test]
    fn protocol_tokens_stay_latin() {
        for lang in [En, Ru, Zh, Fa] {
            let text = detail_text(&Detail::TlsHandshakeTimeout, lang);
            assert!(text.contains("TLS"), "{text}");
            assert!(!text.is_empty());
        }
    }
}
