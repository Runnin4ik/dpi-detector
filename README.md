<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%" alt="DPI Detector Logo">
  <br>
  <i>"Маяк у гаснущего горизонта свободного интернета"</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🔍 DPI Detector (Rust Engine)

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2024-DEA584.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v5.0.0-blue.svg)](https://github.com/Runnin4ik/dpi-detector/releases)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0.svg?logo=telegram&logoColor=white)](https://t.me/DPI_detector)

Быстрый и автономный инструмент для диагностики сетевой цензуры, блокировок сайтов, хостингов, CDN и подмены DNS в России и других регионах.

Полностью переписан на **Rust**: статический бинарник без внешних зависимостей (без Python, системного OpenSSL и glibc), оптимизированный для работы на любых устройствах — от рабочих станций (Windows, Linux, macOS, Android Termux) до домашних роутеров с 16–32 МБ оперативной памяти (Keenetic, OpenWrt, Entware).

> **Инструмент был полезен? Поставь ⭐ в качестве "спасибо"!**  
> 🕊️ Заглядывайте в наш [телеграм-чат](https://t.me/DPI_detector)

---

## 🚀 Быстрый запуск в 1 команду (без установки)

### 🐧 Linux, macOS, роутеры (Keenetic, OpenWrt, Entware) и 📱 Android (Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.sh | sh
```
*Скрипт автоматически определит архитектуру (x86_64, ARM, MIPS), проверит свободную память и скачает подходящую сборку. На роутерах с Entware бинарник ставится в `/opt/bin/dpi-detector`, в Termux — в `$PREFIX/bin/dpi-detector`.*

### 🪟 Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.ps1 | iex
```

Передача параметров при установке:
```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.ps1))) -AppArgs '-t','2','-d','discord.com'
```

---

## 📥 Готовые бинарные сборки

Все сборки статически скомпилированы и готовы к запуску:

| Платформа / Устройство | Архитектура | Бинарник в релизах |
| :--- | :--- | :--- |
| **🪟 Windows 10, 11, Server** | x86_64 | `dpi-detector-windows-x86_64.exe` |
| **🪟 Windows 7, 8, Server 2008/2012** | x86_64 | `dpi-detector-windows-7-x86_64.exe` |
| **🐧 Linux (ПК, Серверы, VPS)** | x86_64 musl | `dpi-detector-linux-x86_64` |
| **📡 Роутеры ARM64** (Keenetic Titan 2/Hopper, RPi 3-5, OpenWrt) | aarch64 musl | `dpi-detector-linux-arm64` |
| **📡 Роутеры ARMv7** (Keenetic Hero/Titan 1, Asus RT-AX58U) | armv7hf musl | `dpi-detector-linux-armv7` (и `-upx`) |
| **📡 Роутеры MIPS LE** (Keenetic Giga/Viva, MT7621, OpenWrt) | mipsel musl | `dpi-detector-linux-mipsel` (и `-upx`) |
| **📡 Роутеры MIPS BE** (Atheros, Qualcomm, OpenWrt) | mips musl | `dpi-detector-linux-mips` (и `-upx`) |
| **🍎 macOS Apple Silicon** (M1–M4) | aarch64 | `dpi-detector-macos-arm64` |
| **🍎 macOS Intel** | x86_64 | `dpi-detector-macos-intel` |
| **📱 Android ARM64** (Termux, ADB) | aarch64 bionic | `dpi-detector-android-arm64` |
| **📱 Android ARM32** (старые ТВ / планшеты) | armv7 bionic | `dpi-detector-android-armv7` |

> Сборки с суффиксом `-upx` сжаты до ~1.4 МБ для устройств с дефицитом Flash/RAM. На ядрах Linux старее 3.17 (например, Xiaomi R3P на ядре 3.4) используйте стандартные сборки без UPX.

---

## 🎯 Возможности и диагностические тесты

В интерактивном меню (TUI) или через аргумент `-t / --tests` доступны следующие тесты:

* **`0` — Сеть и система**: внешний IP, провайдер, AS, страна, тип NAT, определение локальных кэш-серверов Google (GGC), обнаружение активных локальных средств обхода (Zapret, ByeDPI, nfqws).
* **`1` — Доступность DNS**: проверка открытого UDP 53, подмены IP заглушками реестра, доступность защищенных резолверов DoH (Cloudflare, Google, Quad9, Yandex, AdGuard) и DoT.
* **`2` — Доступность сайтов (HTTP, TLS 1.2, TLS 1.3, QUIC)**: проверка целевых ресурсов с пошаговой фиксацией блокировок (SYN Drop, TCP RST на ClientHello, TLS Alert, сброс после SNI, HTTP редирект на заглушку).
* **`3` — TCP 16–20 KB (Обрыв после объема)**: выявление DPI-фильтрации, сбрасывающей соединение к хостингам и CDN после передачи начального объема данных (12–36 КБ).
* **`4` — Подбор белых SNI**: автоматический перебор легитимных доменов для обхода блокировок AS хостингов и CDN.
* **`5` — Доступность Telegram**: проверка связности и сетевой задержки ко всем датацентрам Telegram (DC1–DC5).
* **`6` — Fingerprint / Сибирская блокировка**: диагностика блокировки конкретных отпечатков TLS-рукопожатий (JA3/JA4, ClientHello) серией параллельных запросов с настраиваемой задержкой.
* **`7` — Легенда статусов**: подробное описание всех статусных бейджей (`TCP RST`, `TIMEOUT`, `REDIR`, `TLS DROP` и др.) и таблицы TLS-отпечатков.

> [!WARNING]  
> Если у вас включены системные службы обхода блокировок (zapret, ByeDPI, nfqws), результаты тестов будут отражать их работу. Для замера реальной фильтрации провайдера временно отключите их. При запуске на роутерах с `nfqws2-keenetic` детектор автоматически подскажет, какие правила мешают чистому замеру.

---

## ⚙️ Использование в командной строке (CLI)

Запуск без аргументов открывает интерактивное меню. Для скриптов, cron или автоматизации передавайте параметры CLI:

```text
dpi-detector [ОПЦИИ]

Опции:
  -t, --tests <012...>           Номера тестов для запуска без меню (например: -t 012 или -t 2)
  -d, --domain <DOMAIN>          Проверить конкретный домен (можно повторять: -d discord.com -d yt.com)
  -c, --concurrency <N>          Число параллельных потоков запросов
  -p, --proxy <URL>              SOCKS5-прокси (например: socks5://127.0.0.1:1080)
  -i, --iface <NAME|IP>          Сетевой интерфейс или IP для привязки сокетов (--iface wg0)
  -o, --output <PATH>            Сохранить отчет в файл
      --json                     Вывод результатов в формате JSON для автоматизации
  -l, --lang <LANG>              Язык интерфейса: ru, en, zh, fa, auto [по умолчанию: auto]
      --profile <PROFILE>        Профиль цензуры: ru, ir, cn, global [по умолчанию: ru]
      --fingerprint <FP>         Эмуляция TLS-отпечатка клиента (chrome146, firefox147, safari260, rustls...)
      --ascii                    Режим вывода только в ASCII (для устаревших консолей)
      --legend                   Показать легенду статусов и выйти
  -v, --verbose                  Подробное отладочное логирование
  -h, --help                     Справка
  -V, --version                  Версия программы
```

### Примеры запуска

```bash
# Быстрая проверка доступности сайтов (тест 2) для конкретных доменов
dpi-detector -t 2 -d discord.com -d rutracker.org

# Полный прогон всех диагностик (0-6) с выводом чистого JSON в файл
dpi-detector -t 0123456 --json -o report.json

# Проверка через VPN / сетевой интерфейс WireGuard
dpi-detector -t 2 -i wg0

# Проверка доступности с отпечатком Chrome 146
dpi-detector -t 2 --fingerprint chrome146
```

---

## 📁 Пользовательские списки и конфигурация

Детектор содержит встроенные по умолчанию списки целей, но вы можете переопределить их, положив собственные файлы рядом с бинарником или в рабочую директорию:

* `domains.txt` — список доменов для теста доступности 2.
* `burst-domains.txt` — список доменов для теста отпечатков 6.
* `tcp16.json` — эндпоинты и порты для проверки блокировок по объему (тест 3).
* `whitelist_sni.txt` — пул доверенных SNI для теста 4.
* `config.yml` — расширенные таймауты, DNS-серверы и технические лимиты.

Интерактивное меню автоматически запоминает выбранные настройки (таймаут, язык, интерфейс, потоки) между запусками в `state.json` (в стандартном каталоге конфигурации вашей ОС или роутера).

---

## 🏗️ Сборка из исходников

Для сборки требуется компилятор Rust (`rustup` подтянет версию, указанную в `rust-toolchain.toml`):

```bash
git clone https://github.com/Runnin4ik/dpi-detector.git -b rust
cd dpi-detector
cargo build --release -p dpi-detector
```

Готовый бинарник будет находиться в `target/release/dpi-detector` (`dpi-detector.exe` на Windows).

---

## 💬 Обратная связь и сообщество

* 🕊️ Telegram-чат: [@DPI_detector](https://t.me/DPI_detector)
* 🐛 Баги и предложения: [GitHub Issues](https://github.com/Runnin4ik/dpi-detector/issues)
* 📜 Лицензия: [MIT License](LICENSE)
