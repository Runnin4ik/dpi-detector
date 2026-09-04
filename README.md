<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>"Маяк у гаснущего горизонта свободного интернета"</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🦀 DPI Detector (Native Rust Engine)

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-DEA584.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v5.0.0--alpha.2-blue.svg)](https://github.com/Runnin4ik/dpi-detector/releases)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0.svg?logo=telegram&logoColor=white)](https://t.me/DPI_detector)

Полностью переписанный нативный инструмент для анализа цензуры и блокировок трафика на **чистом Rust**:
* **0 зависимостей**: Никакого Python, C/C++ библиотек или системного OpenSSL. Собрано на `rustls`, `ring` и `RustCrypto`.
* **Легковесный**: Размер бинарника всего **~4.4 МБ**, потребление оперативной памяти в работе — **3–6 МБ RAM**.
* **Максимальная кросс-платформенность**: Нативная поддержка роутеров (MIPS, ARM), Windows (от Windows 7 до 11), Linux musl и macOS.
* **Интерактивный TUI + Batch**: Полноценное стрелочное меню в терминале и быстрый тихий запуск при передаче аргументов командной строки.

---

## 🚀 Быстрый запуск в 1 строку (Без установки)

### 🐧 Linux, macOS, роутеры Keenetic, OpenWrt & Entware

```bash
curl -fsSL https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.sh | sh
```

---

### 🪟 Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.ps1 | iex
```

---

## 📦 Готовые бинарные сборки

Все сборки полностью статичны и не требуют внешних библиотек:

| Платформа / Устройство | Архитектура | Бинарник в релизах |
| :--- | :--- | :--- |
| **Windows 10, 11, Server** | x86_64 | `dpi-detector-windows-x86_64.exe` |
| **Windows 7, 8, Server 2008/2012** | x86_64 | `dpi-detector-windows-7-x86_64.exe` |
| **Linux (PC, Серверы, VPS)** | x86_64 musl | `dpi-detector-linux-x86_64` |
| **Роутеры ARM64** (Keenetic Hopper/Titan 2, RPi, OpenWrt) | aarch64 musl | `dpi-detector-linux-arm64` |
| **Роутеры ARMv7** (Keenetic Titan 1/Hero, Asus RT-AX58U) | armv7hf musl | `dpi-detector-linux-armv7` |
| **Роутеры MIPS LE** (Keenetic Viva/Giga, MT7621, OpenWrt) | mipsel musl | `dpi-detector-linux-mipsel` |
| **Роутеры MIPS BE** (Atheros, Qualcomm, OpenWrt) | mips musl | `dpi-detector-linux-mips` |
| **macOS Apple Silicon** (M1, M2, M3, M4) | aarch64 | `dpi-detector-macos-arm64` |
| **macOS Intel** | x86_64 | `dpi-detector-macos-intel` |

---

## 🛠️ Установка на роутеры (Keenetic / OpenWrt / Entware)

При запуске на роутере скрипт `install.sh`:
1. Автоматически находит директорию `/opt/bin` (Entware) и устанавливает бинарник туда (сохраняется после перезагрузки).
2. Заменяет файл атомарно (`.tmp.$$` -> `dpi-detector`) с проверкой архитектуры через `--version`.
3. Поддерживает запуск напрямую через SSH:

```bash
# Установка и запуск меню
curl -fsSL https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.sh | sh

# Повторный запуск после установки
/opt/bin/dpi-detector
```

---

## ⚙️ Параметры командной строки (CLI)

```text
Использование: dpi-detector [ОПЦИИ]

Опции:
  -t, --tests <TESTS>            Номера тестов (например: -t 1,2,3 или -t "1 2 3" или -t 123)
  -d, --domain <DOMAIN>          Тестируемый домен (или путь к файлу со списком доменов)
      --dns <SERVER>             Пользовательский DNS-сервер для проверки (IP или IP:PORT)
      --ipv4                     Использовать только IPv4
      --ipv6                     Использовать только IPv6
  -c, --concurrency <COUNT>      Количество параллельных потоков (1, 5, 20, 50, 100) [по умолч.: 50]
      --timeout <SECS>           Таймаут сетевых запросов в секундах [по умолчанию: 5]
      --json                     Вывод результатов в формате JSON (для скриптов и автоматизации)
      --lang <LANG>              Язык интерфейса: ru, en, fa, zh, es, ar [по умолчанию: ru]
      --legend                   Показать расшифровку статусов блокировок и выйти
  -h, --help                     Показать справку
  -V, --version                  Показать версию программы
```

### Номера доступных тестов:
* `0` — **Информация о сети и системе** (внешний IP, провайдер, AS, страна, тип NAT)
* `1` — **Доступность DNS-серверов** (проверка UDP 53, DoH Cloudflare/Google/Quad9/Yandex/AdGuard)
* `2` — **Доступность заблокированных сайтов** (HTTP, TLS 1.2, TLS 1.3, классификация типа блокировки)
* `3` — **TCP16 Fat Ping** (детект блокировок CDN и хостингов после 14–34 КБ данных)
* `4` — **Подбор белых SNI** (поиск незаблокированных доменов для обхода DPI)
* `5` — **Блокировки популярных сервисов** (Discord, YouTube, Telegram, Twitter, Instagram и др.)

---

## 🏗️ Сборка из исходников

Для самостоятельной сборки потребуется установленный Rust (версии 1.80+):

```bash
git clone https://github.com/Runnin4ik/dpi-detector.git -b rust
cd dpi-detector
cargo build --release -p dpi-detector
```

Скомпилированный бинарник будет находиться в `target/release/dpi-detector` (`dpi-detector.exe` на Windows).

Для статической сборки под Windows без внешних зависимостей CRT:
```bash
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p dpi-detector
```
