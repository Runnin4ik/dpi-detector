//! Human text for the diagnostic details the engine reports.
//!
//! [`Detail`] is a value, so this is an exhaustive `match`: a new variant does
//! not compile until every language has its wording. Russian is the source
//! language, so the `Ru` column is Russian prose — the Python prototype's own
//! `DET_*` strings were not (a dozen of them were English: `SNI Block
//! (Unrecognized Name)`, `Cert expired`), and pasting one of those back into the
//! `Ru` slot shows English inside a Russian report. `protocol_tokens_stay_latin`
//! and `the_russian_column_is_russian` below pin both halves of that. Protocol
//! tokens inside a detail (`ClientHello`, `TLS`, `SNI`, `KB`) stay Latin in every
//! language (Rule 4).

use super::{get_messages, Language};
use dpi_core::classify::detail::{kb_display, Detail};

/// The same wording in four languages: `ru` is the Russian text.
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
pub(crate) fn detail_text(detail: &Detail, lang: Language) -> String {
    let msg = get_messages(lang);
    match detail {
        Detail::None => String::new(),
        Detail::RstHello => t4(lang, "TCP RST на ClientHello", "TCP RST on ClientHello", "ClientHello 上的 TCP RST", "TCP RST roye ClientHello"),
        Detail::StreamEofHello => t4(lang, "EOF после ClientHello", "EOF after ClientHello", "ClientHello 之后的 EOF", "EOF pas az ClientHello"),
        Detail::StreamRstConnect => t4(lang, "TCP RST от DPI при подключении", "TCP RST received from DPI on connect", "连接时收到 DPI 发送的 TCP RST", "TCP RST az taraf-e DPI dar zaman-e ettesal"),
        Detail::TlsDropHandshake => t4(lang, "TLS DROP (ТСПУ дропнул соединение при TLS handshake)", "TLS DROP (connection dropped during TLS handshake)", "TLS DROP（TLS 握手期间连接被丢弃）", "TLS DROP (ettesal dar zaman-e TLS handshake ghat shod)"),
        Detail::TimeoutConn => t4(lang, "TIMEOUT (Таймаут соединения)", "TIMEOUT (connection timeout)", "TIMEOUT（连接超时）", "TIMEOUT (mohlat-e ettesal)"),
        Detail::TlsRstHello => t4(lang, "TLS RST (ТСПУ разорвал TLS после ClientHello)", "TLS RST (connection reset after ClientHello)", "TLS RST（ClientHello 之后连接被重置）", "TLS RST (ettesal pas az ClientHello reset shod)"),
        Detail::WrongVersion => t4(lang, "Подмена ответа (Wrong Version)", "Response spoofing (Wrong Version)", "响应伪造（Wrong Version）", "Spoofing-e pasokh (Wrong Version)"),
        Detail::GarbageData => t4(lang, "Подмена ответа (Garbage Data)", "Response spoofing (Garbage Data)", "响应伪造（Garbage Data）", "Spoofing-e pasokh (Garbage Data)"),
        Detail::SniBlockUnrecognizedName => t4(lang, "Блок SNI (unrecognized name)", "SNI block (unrecognized name)", "SNI 封锁（unrecognized name）", "Block-e SNI (unrecognized name)"),
        Detail::DpiAlertHandshakeFailure => t4(lang, "Алерт DPI (handshake failure)", "DPI alert (handshake failure)", "DPI 警报（handshake failure）", "Alert-e DPI (handshake failure)"),
        Detail::ProtocolVersionAlert => t4(lang, "Алерт версии протокола", "Protocol version alert", "协议版本警报", "Alert-e version-e protocol"),
        Detail::FakeTlsAlert => t4(lang, "Поддельный TLS Alert", "Fake TLS alert", "伪造的 TLS 警报", "Alert-e TLS-e ja'li"),
        Detail::NoRootCa => t4(lang, "Отсутствуют корневые сертификаты", "Missing root certificates", "缺少根证书", "Certificate haye rishe vojud nadarad"),
        Detail::CertExpired => t4(lang, "Сертификат просрочен", "Certificate expired", "证书已过期", "Certificate monghazi shode ast"),
        Detail::SelfSigned => t4(lang, "Самоподписанный сертификат", "Self-signed certificate", "自签名证书", "Certificate-e self-signed"),
        Detail::HostnameMismatch => t4(lang, "Hostname не совпадает", "Hostname mismatch", "主机名不匹配", "Adam-e tatabogh-e hostname"),
        Detail::FakeCert => t4(lang, "Подмена сертификата", "Certificate spoofing", "证书伪造", "Spoofing-e certificate"),
        Detail::TransferEof => t4(lang, "Обрыв при передаче (EOF)", "Transfer EOF", "传输中断 (EOF)", "Ghat'-e enteghal (EOF)"),
        Detail::HandshakeEof => t4(lang, "Тихий обрыв (Handshake EOF)", "Quiet teardown (handshake EOF)", "静默中断（handshake EOF）", "Ghat'-e khamush (handshake EOF)"),
        Detail::NoTls13 => t4(lang, "Сервер не поддерживает TLS 1.3", "Server has no TLS 1.3", "服务器不支持 TLS 1.3", "Server az TLS 1.3 poshtibani nemikonad"),
        Detail::PoolTimeout => t4(lang, "Нехватка сокетов, снизьте параллелизм", "Socket pool exhausted", "套接字池耗尽", "Socket pool por shod"),
        Detail::TlsHandshakeTimeout => t4(lang, "Таймаут TLS handshake", "TLS handshake timeout", "TLS 握手超时", "Mohlat-e TLS handshake"),
        Detail::TcpSynTimeout => t4(lang, "Таймаут TCP SYN", "TCP SYN timeout", "TCP SYN 超时", "Mohlat-e TCP SYN"),
        Detail::SynTimeoutShort => t4(lang, "Таймаут SYN", "SYN timeout", "SYN 超时", "Mohlat-e SYN"),
        // `Timeout` as a word: the head of a composed detail, never a row of its own.
        Detail::TimeoutWord => t4(lang, "Таймаут", "Timeout", "超时", "Mohlat"),
        Detail::ReadTimeoutWord => t4(lang, "Таймаут чтения", "Read timeout", "读取超时", "Mohlat-e khandan"),
        Detail::WriteTimeoutWord => t4(lang, "Таймаут записи", "Write timeout", "写入超时", "Mohlat-e neveshtan"),
        Detail::Alert(kind) => {
            let name = kind.code();
            t4(
                lang,
                &format!("TLS-алерт ({name})"),
                &format!("TLS alert ({name})"),
                &format!("TLS 警报（{name}）"),
                &format!("Alert-e TLS ({name})"),
            )
        }
        Detail::StackFailure(kind) => {
            let name = kind.code();
            t4(
                lang,
                &format!("TLS-стек ({name})"),
                &format!("TLS stack ({name})"),
                &format!("TLS 协议栈（{name}）"),
                &format!("Khatay-e TLS ({name})"),
            )
        }
        Detail::UnknownConnectionFailure => t4(lang, "Неизвестная ошибка соединения", "Unknown connection failure", "未知连接错误", "Khata-ye nashenakhte dar ettesal"),
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
        Detail::IcmpAdminProhibited => t4(lang, "ICMP: административно запрещено (фильтр провайдера)", "ICMP administratively prohibited (provider filter)", "ICMP 管理禁止（运营商过滤）", "ICMP admin prohibited (filter-e provider)"),
        Detail::Ipv6Unsupported => t4(lang, "IPv6 не поддерживается/отключён", "IPv6 not supported/disabled", "IPv6 不受支持或已禁用", "IPv6 poshtibani nemishavad ya ghayr-e fa'al ast"),
        // Composed: the head is itself a detail, the offset keeps its unit.
        Detail::AtKb { head, kb } => {
            format!("{} {} {}", detail_text(head, lang), msg.detail_at, kb_display(*kb))
        }
        // The stage stays a protocol token.
        Detail::TimeoutStage { stage } => {
            format!("{} ({})", detail_text(&Detail::TimeoutWord, lang), stage)
        }
        Detail::IspBlockpage { arrow: true, ip } => format!("{} -> {}", msg.detail_isp_stub, ip),
        Detail::IspBlockpage { arrow: false, ip } => format!("{} {}", msg.detail_isp_stub, ip),
        Detail::LocalIp { ip } => format!("{} -> {}", msg.detail_local_ip, ip),
        Detail::HttpStatus(code) => format!("HTTP {}", code),
        // The target of a redirect is a host and a scheme, not prose: the arrow
        // is the same in every language (and maps to `->` on an ASCII console).
        Detail::Redirect { host } => format!("→ {host}"),
        Detail::UpgradeHttps { status: Some(code) } => format!("{code} → https"),
        Detail::UpgradeHttps { status: None } => "→ https".to_string(),
        Detail::Elapsed(secs) => format!("{:.1}s", secs),
        // Free text from the OS or the TLS stack: appended as it came.
        Detail::Other(text) => text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Language::*;
    use dpi_core::classify::detail::{AlertKind, StackKind};

    #[test]
    fn composed_details_keep_their_tokens() {
        let stage = Detail::TimeoutStage { stage: "reading_data".into() };
        assert_eq!(detail_text(&stage, Zh), "超时 (reading_data)");
        assert_eq!(detail_text(&stage, Fa), "Mohlat (reading_data)");
        assert_eq!(detail_text(&Detail::at_kb(Detail::TimeoutWord, 20.0), Zh), "超时 在 20KB");
        let at = Detail::at_kb(Detail::ReadTimeoutWord, 24.0);
        assert_eq!(detail_text(&at, Zh), "读取超时 在 24KB");
        assert_eq!(
            detail_text(&Detail::at_kb(Detail::ReadTimeoutWord, 8.0), Fa),
            "Mohlat-e khandan dar 8KB"
        );
        assert_eq!(detail_text(&at, Ru), "Таймаут чтения на 24KB");
        let stub = Detail::IspBlockpage { arrow: true, ip: "1.1.1.1".into() };
        assert_eq!(detail_text(&stub, En), "ISP blockpage -> 1.1.1.1");
        assert_eq!(detail_text(&Detail::LocalIp { ip: "10.0.0.1".into() }, Zh), "本地 IP -> 10.0.0.1");
        assert_eq!(detail_text(&Detail::HttpStatus(451), Zh), "HTTP 451");
        assert_eq!(
            detail_text(&Detail::StackFailure(StackKind::DecryptError), Ru),
            "TLS-стек (decrypt_error)"
        );
        assert_eq!(
            detail_text(&Detail::StackFailure(StackKind::PeerMisbehaved), En),
            "TLS stack (peer_misbehaved)"
        );
        // A redirect reads as its target in every language, and an https hop
        // names the status that carried it when one is known.
        let foreign = Detail::Redirect { host: "www.facebook.com".into() };
        for lang in [En, Ru, Zh, Fa] {
            assert_eq!(detail_text(&foreign, lang), "→ www.facebook.com");
        }
        assert_eq!(detail_text(&Detail::UpgradeHttps { status: Some(301) }, Ru), "301 → https");
        assert_eq!(detail_text(&Detail::UpgradeHttps { status: None }, Ru), "→ https");
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

    /// A named alert shows the description the peer sent, in every language,
    /// and the description itself stays Latin (Rule 4).
    #[test]
    fn a_named_alert_shows_its_description() {
        let alert = Detail::Alert(AlertKind::IllegalParameter);
        assert_eq!(detail_text(&alert, Ru), "TLS-алерт (illegal_parameter)");
        assert_eq!(detail_text(&alert, En), "TLS alert (illegal_parameter)");
        assert_eq!(detail_text(&alert, Zh), "TLS 警报（illegal_parameter）");
        assert_eq!(detail_text(&alert, Fa), "Alert-e TLS (illegal_parameter)");
        for lang in [En, Ru, Zh, Fa] {
            let text = detail_text(&alert, lang);
            assert!(text.contains("TLS") && text.contains("illegal_parameter"), "{text}");
        }
    }

    /// Rule 6: the `Ru` column is Russian. Every detail that carries prose is
    /// listed, and its `Ru` text has to contain a Cyrillic letter — a token-only
    /// text is the failure this catches, not a translation.
    ///
    /// The exhaustive `match` cannot guard this: a new variant fails to compile
    /// without *a* string, not without a *Russian* one. The Python prototype's
    /// own `DET_*` constants were English for a dozen details (`Cert expired`,
    /// `SNI Block (Unrecognized Name)`), and copying one back into the `Ru` slot
    /// put English inside a Russian report — one row of a Russian table reading
    /// `DPI closed connection immediately after TLS ClientHello` beside another
    /// reading `TCP RST на ClientHello`. Shapes that are machine text in every
    /// language (`None`, `Elapsed`, `HttpStatus`, `Redirect`, `UpgradeHttps`,
    /// and `Other`, which is raw OS/library text) are out of scope, as are the
    /// tokens inside the listed ones (Rule 4).
    ///
    /// The list is written out because the enum cannot be iterated; a variant
    /// added to the enum does not fail here, so add it when its wording lands.
    #[test]
    fn the_russian_column_is_russian() {
        let prose = [
            Detail::RstHello,
            Detail::StreamEofHello,
            Detail::StreamRstConnect,
            Detail::TlsDropHandshake,
            Detail::TimeoutConn,
            Detail::TlsRstHello,
            Detail::WrongVersion,
            Detail::GarbageData,
            Detail::SniBlockUnrecognizedName,
            Detail::DpiAlertHandshakeFailure,
            Detail::ProtocolVersionAlert,
            Detail::FakeTlsAlert,
            Detail::Alert(AlertKind::IllegalParameter),
            Detail::StackFailure(StackKind::DecryptError),
            Detail::NoRootCa,
            Detail::CertExpired,
            Detail::SelfSigned,
            Detail::HostnameMismatch,
            Detail::FakeCert,
            Detail::TransferEof,
            Detail::HandshakeEof,
            Detail::NoTls13,
            Detail::PoolTimeout,
            Detail::TlsHandshakeTimeout,
            Detail::TcpSynTimeout,
            Detail::SynTimeoutShort,
            Detail::TimeoutWord,
            Detail::ReadTimeoutWord,
            Detail::WriteTimeoutWord,
            Detail::DomainNotFound,
            Detail::DnsTimeoutUnavailable,
            Detail::DnsError,
            Detail::ConnRefused,
            Detail::RstAfterHandshake,
            Detail::ConnReset,
            Detail::Aborted,
            Detail::TcpAborted,
            Detail::NetUnreach,
            Detail::HostUnreach,
            Detail::IcmpAdminProhibited,
            Detail::UnknownConnectionFailure,
            Detail::Ipv6Unsupported,
            Detail::at_kb(Detail::TimeoutWord, 24.0),
            Detail::TimeoutStage { stage: "reading_data".into() },
            Detail::IspBlockpage { arrow: true, ip: "192.0.2.1".into() },
            Detail::LocalIp { ip: "192.0.2.1".into() },
        ];
        for detail in &prose {
            let text = detail_text(detail, Ru);
            assert!(
                text.chars().any(|c| ('\u{0400}'..='\u{04ff}').contains(&c)),
                "{} reads {text:?} in Russian",
                detail.code()
            );
        }
    }
}
