//! Canonical diagnostic detail strings used across classification and probing.

pub const DET_RST_HELLO: &str = "TCP RST на ClientHello";
pub const DET_STREAM_RST_HELLO: &str = "TCP RST on ClientHello";
pub const DET_STREAM_EOF_HELLO: &str = "DPI closed connection immediately after TLS ClientHello";
pub const DET_STREAM_RST_CONNECT: &str = "TCP RST received from DPI on connect";
pub const DET_TLS_DROP_HANDSHAKE: &str = "TLS DROP (ТСПУ дропнул соединение при TLS handshake)";
pub const DET_TIMEOUT_CONN: &str = "TIMEOUT (Таймаут соединения)";
pub const DET_TLS_RST_HELLO: &str = "TLS RST (ТСПУ разорвал TLS после ClientHello)";

pub const DET_WRONG_VERSION: &str = "Подмена ответа (Wrong Version)";
pub const DET_GARBAGE_DATA: &str = "Подмена ответа (Garbage Data)";
pub const DET_SNI_BLOCK_UNREC: &str = "SNI Block (Unrecognized Name)";
pub const DET_DPI_ALERT_HS_FAIL: &str = "DPI Alert (Handshake Failure)";
pub const DET_PROTOCOL_VERSION_ALERT: &str = "Protocol Version Alert";
pub const DET_FAKE_TLS_ALERT: &str = "Поддельный TLS Alert";

pub const DET_NO_ROOT_CA: &str = "Отсутствуют корневые сертификаты";
pub const DET_CERT_EXPIRED: &str = "Cert expired";
pub const DET_SELF_SIGNED: &str = "Self-signed cert";
pub const DET_HOSTNAME_MISMATCH: &str = "Hostname mismatch";
pub const DET_FAKE_CERT: &str = "Подмена сертификата";

pub const DET_TRANSFER_EOF: &str = "Обрыв при передаче (EOF)";
pub const DET_HANDSHAKE_EOF: &str = "Тихий обрыв (Handshake EOF)";
pub const DET_NO_TLS13: &str = "Server has no TLS 1.3";

pub const DET_POOL_TIMEOUT: &str = "Нехватка сокетов, снизьте параллелизм";
pub const DET_TLS_HANDSHAKE_TIMEOUT: &str = "TLS Handshake timeout";
pub const DET_TCP_SYN_TIMEOUT: &str = "TCP SYN timeout";
/// Short form used by the Telegram DC ping column.
pub const DET_SYN_TIMEOUT_SHORT: &str = "SYN timeout";
pub const DET_SEND_TIMEOUT: &str = "Таймаут отправки данных";
pub const DET_READ_TIMEOUT: &str = "Таймаут чтения данных";

/// Plain word used to build `"Timeout (<stage>)"` and `"Timeout <n>KB"`.
pub const DET_TIMEOUT_WORD: &str = "Timeout";
/// Read-transfer timeout: standalone, with a `KB` offset, or in the `<head> at <n>KB` pair.
pub const DET_READ_TIMEOUT_WORD: &str = "Read timeout";
pub const DET_READ_TIMEOUT_WORD_CAPS: &str = "Read Timeout";
pub const DET_WRITE_TIMEOUT_WORD: &str = "Write Timeout";
/// Infix/suffix of the offset details (`"Read Timeout at 24KB"`). Classification
/// logic tests for this marker, so it is part of the wire format, not prose.
pub const DET_AT_KB_MARKER: &str = " at ";
pub const DET_KB_SUFFIX: &str = "KB";
pub const DET_ALERT_HANDSHAKE: &str = "Handshake alert";
pub const DET_ALERT_SNI: &str = "SNI alert";
pub const DET_ALERT_VERSION: &str = "Version alert";
pub const DET_ALERT_TLS: &str = "TLS alert";
pub const DET_UNKNOWN_CONN_FAILURE: &str = "Unknown connection failure";

/// Every canonical detail that carries prose (used by the i18n coverage test).
/// The three `DET_ISP_*`/`DET_LOCAL_IP_*` markers are prefixes, not details.
pub const ALL_DET_DETAILS: &[&str] = &[
    DET_RST_HELLO,
    DET_STREAM_RST_HELLO,
    DET_STREAM_EOF_HELLO,
    DET_STREAM_RST_CONNECT,
    DET_TLS_DROP_HANDSHAKE,
    DET_TIMEOUT_CONN,
    DET_TLS_RST_HELLO,
    DET_WRONG_VERSION,
    DET_GARBAGE_DATA,
    DET_SNI_BLOCK_UNREC,
    DET_DPI_ALERT_HS_FAIL,
    DET_PROTOCOL_VERSION_ALERT,
    DET_FAKE_TLS_ALERT,
    DET_NO_ROOT_CA,
    DET_CERT_EXPIRED,
    DET_SELF_SIGNED,
    DET_HOSTNAME_MISMATCH,
    DET_FAKE_CERT,
    DET_TRANSFER_EOF,
    DET_HANDSHAKE_EOF,
    DET_NO_TLS13,
    DET_POOL_TIMEOUT,
    DET_TLS_HANDSHAKE_TIMEOUT,
    DET_TCP_SYN_TIMEOUT,
    DET_SYN_TIMEOUT_SHORT,
    DET_SEND_TIMEOUT,
    DET_READ_TIMEOUT,
    DET_ALERT_HANDSHAKE,
    DET_ALERT_SNI,
    DET_ALERT_VERSION,
    DET_ALERT_TLS,
    DET_UNKNOWN_CONN_FAILURE,
    DET_TIMEOUT_WORD,
    DET_READ_TIMEOUT_WORD,
    DET_READ_TIMEOUT_WORD_CAPS,
    DET_WRITE_TIMEOUT_WORD,
    DET_DOMAIN_NOT_FOUND,
    DET_DNS_TIMEOUT_UNAVAIL,
    DET_DNS_ERROR,
    DET_CONN_REFUSED,
    DET_RST_AFTER_HANDSHAKE,
    DET_CONN_RESET,
    DET_ABORTED,
    DET_TCP_ABORTED,
    DET_NET_UNREACH,
    DET_HOST_UNREACH,
    DET_IPV6_UNSUPPORTED,
    DET_IPV6_NOT_SUPPORTED_SHORT,
];

pub const DET_DOMAIN_NOT_FOUND: &str = "Домен не найден";
pub const DET_DNS_TIMEOUT_UNAVAIL: &str = "DNS таймаут/недоступен";
pub const DET_DNS_ERROR: &str = "Ошибка DNS";

pub const DET_CONN_REFUSED: &str = "TCP соединение отклонено";
pub const DET_RST_AFTER_HANDSHAKE: &str = "TCP RST после handshake";
pub const DET_CONN_RESET: &str = "TCP соединение сброшено";
pub const DET_ABORTED: &str = "Соединение прервано (Abort)";
pub const DET_TCP_ABORTED: &str = "TCP соединение прервано";

pub const DET_NET_UNREACH: &str = "Нет маршрута (ICMP unreach)";
pub const DET_HOST_UNREACH: &str = "Нет маршрута до хоста";

pub const DET_IPV6_UNSUPPORTED: &str = "IPv6 не поддерживается/отключён";
pub const DET_IPV6_NOT_SUPPORTED_SHORT: &str = "IPv6 не поддерживается";

pub const DET_ISP_STUB_ARROW: &str = "Заглушка провайдера -> ";
pub const DET_ISP_STUB_SPACE: &str = "Заглушка провайдера ";
pub const DET_LOCAL_IP_ARROW: &str = "Локальный IP -> ";
