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
* **`6` — Fingerprint / Сибирская блокировка**: диагностика блокировки конкретных отпечатков TLS-рукопожатий (JA3/JA4, ClientHello) серией параллельных запросов с настраиваемой задержкой; с `--burst-alpn h3` та же серия идёт QUIC-Initial'ами по UDP 443.
* **`7` — Легенда статусов**: подробное описание всех статусных бейджей (`TCP RST`, `TIMEOUT`, `REDIR`, `TLS DROP` и др.) и таблицы TLS-отпечатков.

Ключ, по которому форма блокируется, — **упорядоченный список расширений** (значения GREASE не в счёт): то поле, которое JA3 сохраняет, а JA4 сортирует и потому теряет. Внутри списка отдельно читается **место `encrypted_client_hello`**: настоящий Chrome ставит его перед `key_share`, и форма с ECH последним отвечает там, где форма с ним в середине падает — измерено на `CHROME 146` на одном хосте в одну минуту: `8/8` против `0/8`, при совпадающих JA4, наборе расширений, телах и длине. Профили Chrome 119+ держат ECH на месте браузера, поэтому просадки на таком хосте видны и в детекторе; проверить, что режет именно порядок, можно `--burst-variant ext-order:…` — он пинит порядок и выключает перемешивание.

> [!WARNING]  
> Если у вас включены системные службы обхода блокировок (zapret, ByeDPI, nfqws), результаты тестов будут отражать их работу. Для замера реальной фильтрации провайдера временно отключите их. При запуске на роутерах с `nfqws2-keenetic` детектор автоматически подскажет, какие правила мешают чистому замеру.

---

## ⚙️ Использование в командной строке (CLI)

Запуск без аргументов открывает интерактивное меню. Для скриптов, cron или автоматизации передавайте параметры CLI:

```text
Использование: dpi-detector [ОПЦИИ]

Опции:
  -t, --tests <TESTS>            Строка выбора тестов (например, '012', '1', '2')
      --json                     Вывод в машиночитаемом JSON
  -v, --verbose                  Подробное / отладочное логирование
  -l, --lang <LANG>              Язык интерфейса (ru, en, zh, fa, auto). По умолчанию auto
      --profile <PROFILE>        Региональный профиль цензуры (ru, ir, cn, global) [по умолчанию: ru]
      --legend                   Показать легенду статусов и выйти
  -p, --proxy <URL>              URL SOCKS5-прокси (например, socks5://127.0.0.1:1080)
  -i, --iface <NAME>             Интерфейс, через который идут проверки: имя устройства привязывает сокеты к нему, как curl --interface, а его адрес привязывает источник и оставляет выбор устройства таблице маршрутов; по умолчанию выбирает таблица маршрутов (--iface wg0, --iface 172.16.0.2)
  -c, --concurrency <N>          Лимит параллельных запросов
  -d, --domain <DOMAIN>          Конкретные домены для проверки (флаг можно повторять: -d vk.com -d ya.ru)
  -o, --output <PATH>            Путь к файлу отчёта
      --domains <PATH>           Путь к файлу со списком доменов
      --preset <PRESET>          Пресет целей теста 2: default, youtube, ru [по умолчанию: default]
      --tcp16 <PATH>             Путь к файлу целей TCP16
      --ascii                    Только ASCII для старых консолей (без Unicode-глифов и рамок)
      --fingerprint <PROFILE>    Профиль отпечатка: ClientHello, User-Agent с заголовками и преамбула HTTP/2 одной закреплённой версии клиента; имена и воспроизводимые версии печатает --legend
      --burst <N>                Fingerprint/Сибирская блокировка (тест 6): соединений на домен, внахлёст [1–100, по умолчанию: 10]
      --burst-timeout <SECONDS>  Тест 6: таймаут рукопожатия, секунды [по умолчанию: 8]; запрос после него ждёт общий TIMEOUT
      --burst-gap <MS>           Тест 6: задержка между стартами попыток, мс [0–1000, по умолчанию: 20]; 0 — весь раунд стартует в один момент
      --burst-profiles <LIST>    Fingerprint для теста 6: all или имена профилей через запятую; список печатает --legend [по умолчанию: набор по умолчанию]
      --burst-tls <VERSION>      TLS для теста 6: 1.3+1.2 (предложение браузера, ответ должен быть 1.3)|1.3 (только 1.3)|1.2 (только 1.2) [по умолчанию: 1.3+1.2]
      --burst-alpn <PROTOCOL>    ALPN для теста 6: h2 (предлагает h2 с откатом на http/1.1)|http/1.1 (только http/1.1)|h3 (QUIC по UDP 443, TLS 1.3; ось TLS не применяется) [по умолчанию: h2]
      --burst-variant <DELTA>    Тест 6, вариант: одна правка ClientHello каждого профиля, чтобы вердикт читался против формы, отличающейся одним полем — -ext:ID, ext-body:ID:HEX, +ext:ID, groups:A,B,…, key-shares:A,B,…, ext-order:A,B,… (0x0a0a — слот GREASE), ech-len:N, padding:N, no-padding, sigalg-swap, +grease, +group:ID, alpn-reverse; `;` применяет несколько сразу [по умолчанию: нет]
      --trace [<PATH>]           Трассировка теста 6: строка на каждую попытку (раунд, отпечаток, домен, статус, деталь, мс); без пути — в stderr, с путём — в указанный файл [по умолчанию: выключено]
  -h, --help                     Показать справку
  -V, --version                  Показать версию
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

Детектор содержит встроенные по умолчанию списки целей (в исходниках они лежат в каталоге `data/`), но вы можете переопределить их, положив собственные файлы с теми же именами рядом с бинарником или в рабочую директорию:

* `domains.txt` — список доменов для теста доступности 2 (пресет `default`).
* `domains-youtube.txt` — пресет `youtube`: видеохостинг, его CDN и кэши Google внутри операторов (GGC).
* `domains-ru.txt` — пресет `ru`: российские сервисы, которые ведут себя иначе при зарубежном адресе.
* `burst-domains.txt` — список доменов для теста отпечатков 6.
* `tcp16.json` — эндпоинты и порты для проверки блокировок по объему (тест 3).
* `whitelist_sni.txt` — пул доверенных SNI для теста 4.
* `config.yml` — расширенные таймауты, DNS-серверы и технические лимиты.

Пресет целей теста 2 выбирается флагом `--preset default|youtube|ru` или строкой «Пресет доменов» в интерактивном меню, и запоминается между запусками. Явный `-d` или `--domains <путь>` старше пресета: список, который вы назвали, и есть цель прогона. В `--json` выбранный пресет виден в поле `domain_preset`.

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
