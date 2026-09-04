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
            Self::En => "En",
            Self::Ru => "Ru",
            Self::Fa => "Fa",
            Self::Zh => "Zh",
            Self::Es => "Es",
            Self::Ar => "Ar",
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
            menu_test_dns: "Проверка доступности DNS-серверов",
            menu_test_domains: "Проверка доступности доменов",
            menu_test_tcp: "Проверка TCP 16–20 KB блокировки",
            menu_test_sni: "Поиск белых SNI для ASN",
            menu_test_telegram: "Проверка Telegram (замедление/блокировка)",
            menu_test_legend: "Легенда статусов (справка)",
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
            menu_language: "زبان",
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
            menu_language: "语言",
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
            menu_language: "Idioma",
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
            menu_language: "اللغة",
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
        },
    }
}

/// Prints the full diagnostic status legend (mirrors `cli/ui.py::print_legend`).
/// Terms stay Latin; descriptions follow the selected language (en/ru full,
/// other languages fall back to English descriptions).
pub fn print_legend(lang: Language, msg: &Messages) {
    let _ = msg;
    // Only en/ru ship full legend translations; every other language falls
    // back to English (never Russian), as documented above.
    let russian = lang == Language::Ru;
    let title = if russian {
        "\nЛегенда статусов:\n"
    } else {
        "\nStatus legend:\n"
    };
    println!("{}", title);
    let sections = if russian {
        legend_sections()
    } else {
        legend_sections_en()
    };
    for (section, items) in &sections {
        println!("  {}", section);
        for (term, desc) in items {
            println!("    \x1b[36m{:<14}\x1b[0m \x1b[2m{}\x1b[0m", term, desc);
        }
        println!();
    }
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
            // Interactive checkbox menu: every string present in all languages.
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
            // Digits 0-6 map to their checkbox labels; technical tokens stay Latin.
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
}
