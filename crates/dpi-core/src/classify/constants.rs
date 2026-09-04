//! Canonical diagnostic detail strings used across classification and probing.

pub const DET_RST_HELLO: &str = "TCP RST на ClientHello";
pub const DET_STREAM_RST_HELLO: &str = "TCP RST on ClientHello";
pub const DET_STREAM_EOF_HELLO: &str = "DPI closed connection immediately after TLS ClientHello";
pub const DET_STREAM_RST_CONNECT: &str = "TCP RST received from DPI on connect";

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
pub const DET_SEND_TIMEOUT: &str = "Таймаут отправки данных";
pub const DET_READ_TIMEOUT: &str = "Таймаут чтения данных";

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
