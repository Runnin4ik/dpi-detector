<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>"Маяк у гаснущего горизонта свободного интернета"</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🦀 DPI Detector (Native Rust Engine)

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-DEA584.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v5.0.0--alpha.11-blue.svg)](https://github.com/Runnin4ik/dpi-detector/releases)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0.svg?logo=telegram&logoColor=white)](https://t.me/DPI_detector)

Нативный инструмент для анализа цензуры и блокировок трафика на **чистом Rust**:

* **Никаких внешних зависимостей**: без сторонних рантаймов, без C/C++ библиотек и системного OpenSSL — только `rustls`, `ring` и `RustCrypto`.
* **Легковесный**: статический бинарник ≈3.9 МБ (4–6 МБ на роутерных сборках, UPX — ≈1.4 МБ), потребление оперативной памяти в работе — **3–6 МБ RAM**.
* **Максимальная кросс-платформенность**: нативная поддержка роутеров (MIPS, ARM), Windows (от Windows 7 до 11), Linux musl, macOS и Android (Termux).
* **Интерактивный TUI + Batch**: полноценное стрелочное меню в терминале и быстрый тихий запуск при передаче аргументов командной строки.

---

## 🚀 Быстрый запуск в 1 строку (Без установки)

### 🐧 Linux, macOS, роутеры Keenetic, OpenWrt & Entware

```bash
curl -fsSL https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.sh | sh
```
### 📱 Android (Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/Runnin4ik/dpi-detector/rust/install.sh | sh
```
Скрипт автоматически определит Termux, установит нативный Android-бинарник в `$PREFIX/bin/dpi-detector` и запустит его. Для повторного запуска достаточно ввести `dpi-detector`.

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
| **Роутеры ARMv7** (Keenetic Titan 1/Hero, Asus RT-AX58U) | armv7hf musl | `dpi-detector-linux-armv7` (и `-upx`) |
| **Роутеры MIPS LE** (Keenetic Viva/Giga, MT7621, OpenWrt) | mipsel musl | `dpi-detector-linux-mipsel` (и `-upx`) |
| **Роутеры MIPS BE** (Atheros, Qualcomm, OpenWrt) | mips musl | `dpi-detector-linux-mips` (и `-upx`) |
| **macOS Apple Silicon** (M1, M2, M3, M4) | aarch64 | `dpi-detector-macos-arm64` |
| **macOS Intel** | x86_64 | `dpi-detector-macos-intel` |
| **Android ARM64** (Смартфоны, планшеты, Termux, ADB) | aarch64 bionic | `dpi-detector-android-arm64` |
| **Android ARM32** (Старые устройства, Android TV) | armv7 bionic | `dpi-detector-android-armv7` |

---

## 🛠️ Установка на роутеры (Keenetic / OpenWrt / Entware)

При запуске на роутере скрипт `install.sh`:
1. Автоматически находит директорию `/opt/bin` (Entware) и устанавливает бинарник туда (сохраняется после перезагрузки).
2. **Контролирует свободное место**: если на накопителе осталось `< 7 МБ`, скрипт автоматически скачивает компактную версию со сжатием UPX (~1.4 МБ вместо ~3.9 МБ), защищая роутер от переполнения Flash или `tmpfs`.
3. Заменяет файл атомарно (`.tmp.$$` -> `dpi-detector`) с проверкой архитектуры через `--version` (при сбое UPX автоматически переключается на стандартный бинарник).
4. Поддерживает принудительный выбор версии: `DPI_UPX=1` (компактная) или `DPI_UPX=0` (стандартная).
5. Поддерживает запуск напрямую через SSH:

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
  -t, --tests <TESTS>            Строка выбора тестов (например, '012', '1', '2')
      --json                     Вывод в машиночитаемом JSON
  -v, --verbose                  Подробное / отладочное логирование
  -l, --lang <LANG>              Язык интерфейса (ru, en, zh, fa, auto). По умолчанию auto
      --profile <PROFILE>        Региональный профиль цензуры (ru, ir, cn, global) [по умолчанию: ru]
      --legend                   Показать легенду статусов и выйти
  -p, --proxy <URL>              URL SOCKS5-прокси (socks5://127.0.0.1:1080)
  -c, --concurrency <N>          Лимит параллельных запросов
  -d, --domain <DOMAIN>          Конкретные домены для проверки (флаг можно повторять: -d vk.com -d ya.ru)
  -o, --output <PATH>            Путь к файлу отчёта
      --domains <PATH>           Путь к файлу со списком доменов
      --tcp16 <PATH>             Путь к файлу целей TCP16
      --ascii                    Только ASCII для старых консолей (без Unicode-глифов и рамок)
      --fingerprint <PROFILE>    Профиль отпечатка (rustls|custom|chrome|safari): ClientHello, User-Agent и заголовки, преамбула HTTP/2. custom — форма Firefox 133, chrome — Chrome 107 / Edge 99-101, safari — Safari 15.5-18.4 из curl-impersonate; все предлагают h2
      --burst <N>                Fingerprint/Сибирская блокировка (тест 6): одновременных запросов за раунд [по умолчанию: 4]
      --burst-timeout <SECONDS>  Тест 6: таймаут одного рукопожатия, секунды [по умолчанию: 8]
      --burst-profiles <LIST>    Fingerprint для теста 6: all|rustls,custom(firefox133),chrome(chrome107),safari(safari155) [по умолчанию: all]
      --burst-tls <VERSION>      Версия TLS для теста 6: 1.2|1.3 [по умолчанию: 1.3]
      --burst-alpn <PROTOCOL>    ALPN для теста 6: h2 (предлагает h2 с откатом на http/1.1)|http/1.1 (только http/1.1) [по умолчанию: h2]
  -h, --help                     Показать справку
  -V, --version                  Показать версию
```

Справка и все сообщения локализованы: `dpi-detector --lang en --help`, `--lang zh --help`, `--lang fa --help`. Любой другой текст интерфейса — таблицы, легенда, предупреждения — тоже следует за `--lang`. Машинный вывод `--json` от языка не зависит: ключи и значения `detail` не переводятся.

### Локализация (`crates/dpi-core/src/i18n`)

* `Messages` - по одному полю на строку, четыре блока (`En`, `Ru`, `Zh`, `Fa`); шаблоны используют `{}`.
* `legend_sections*()` - таблицы `--legend`; `details.rs` - текст для деталей `DET_*` (в русском блоке строка выводится как есть).
* Язык Farsi рендерится **Finglish** (латиница, без персидской графики и диакритики).
* Статусные бейджи и имена протоколов (`OK`, `BLOCKED`, `TLS RST`, `SNI`, `ClientHello`) остаются латиницей в любом языке — так цифры, IP-адреса и строки логов читаются одинаково во всех локалях.

### Номера доступных тестов:
* `0` — **Информация о сети и системе** (внешний IP, провайдер, AS, страна, тип NAT)
* `1` — **Доступность DNS-серверов** (проверка UDP 53, DoH Cloudflare/Google/Quad9/Yandex/AdGuard)
* `2` — **Доступность сайтов** (HTTP, TLS 1.2, TLS 1.3, классификация блокировок DPI)
* `3` — **Доступность CDN и хостингов (тест 16 KB)** (детект сброса соединений после 14–34 КБ данных)
* `4` — **Поиск белых SNI** (перебор рабочих SNI для заблокированных AS: цель отбирается по 16 KB-обрыву, TLS RST и TLS DROP)
* `5` — **Доступность Telegram** (проверка доступности и скорости датацентров DC1–DC5)
* `6` — **Fingerprint/Сибирская блокировка** (N одновременных TLS-рукопожатий на один домен выбранными отпечатками: сколько ответили и что именно перестало отвечать)
* `7` — **Легенда статусов** (справка по вердиктам)

### Тест 6: Fingerprint/Сибирская блокировка

При выборе теста `6` открывается свой экран настроек: число одновременных рукопожатий, таймаут одного рукопожатия **в секундах**, **версия TLS** (`1.2`/`1.3`), **протокол HTTP в ALPN** (`h2` — как у браузеров, с откатом на `http/1.1`, или `http/1.1` — только он), домен (в поле показан хост, который проверял прошлый прогон; первый набранный символ заменяет его, а пустое поле — весь список, как в тесте `2`; вставленный URL приводится к имени хоста тем же очистителем, что и список из конфига) и **Fingerprint** (по умолчанию все). Поле домена подсвечивается: серый фон — строка выбрана, синий — в поле идёт ввод. `Q`/`Esc` отменяет тест.

На каждый домен и отпечаток выполняется N одновременных рукопожатий выбранной версии TLS — отдельные TCP-соединения, свежие сессии без resumption. Две оси дают 4 комбинации, и они измеряют разные вещи: `1.3` против `1.2` — реакцию на версию протокола, `h2` против `http/1.1` — реакцию на ALPN (некоторые триггеры срабатывают именно на h2-хелло; JA4 при этом меняет поле ALPN, `h2` → `h1`). В таблице `M/N` по каждому отпечатку (зелёный — ответили все, жёлтый — часть, красный — никто), в колонке «Детали» — самый частый вердикт отказа (`TLS RST`, `TLS DROP`, `SYN DROP`, …). Тест идёт последним: серия рукопожатий может «сжечь» цель на время, и измерения после неё недействительны.

Во время прогона печатается одна живая строка `Тестируем: CHROME 107 3/4  12/35 · 00:04` — какая форма сейчас в эфире, который это раунд из скольких, сколько хостов раунда готово и сколько идёт время. Отдельной шапки с настройками и блок «Итог» тест не выводит: отпечаток с версией и так виден в колонках таблицы, а пустой итог не рисуется.

Из неинтерактивного запуска настройки задаются флагами `--burst`, `--burst-timeout`, `--burst-profiles`, `--burst-tls`, `--burst-alpn`; в `--json` результат лежит в ключе `results.fingerprint_burst` (вместе с `tls` и `alpn` этого прогона).

### Профили отпечатка (`--fingerprint`)

Профиль задаёт три слоя сразу, и все три взяты из одного и того же набора `curl-impersonate v2.2.2`, поэтому клиент, выглядящий как `curl_chrome107` в одном слое, выглядит так же и в остальных:

| Слой | Что воспроизводится | Что нет |
| --- | --- | --- |
| TLS | список шифров и их порядок, группы, `signature_algorithms`, ALPN, порядок расширений, GREASE, ALPS, padding до 512, сжатие сертификата; тесты пинуют JA3 и JA4 против бандла | ECH (синтез ломает рукопожатие с Google и Cloudflare); в прогонах с пришпиленной версией (`tls13`/`tls12`) в `supported_versions` нет фолбэка `0x0303`, который шлёт оригинал — JA3/JA4 этого не видят, читающий тело middlebox видит |
| HTTP | `User-Agent` и набор заголовков клиента в его порядке (`sec-ch-ua*`, `accept`, `sec-fetch-*`, `accept-language`; у Firefox ещё `priority` и `te`) | `accept-encoding` всегда `identity`: тесты 2–4 считают байты до обрыва, а согласованное сжатие сделало бы эти числа зависящими от сжимаемости ответа |
| HTTP/2 | значения `SETTINGS` и то, какие из них отправляются, плюс оконный `WINDOW_UPDATE` | порядок псевдозаголовков (`m,s,a,p` — порядок hyper; Chrome шлёт `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,p,a`) и приоритет на `HEADERS` (h2 0.4 не умеет приоритеты) |

Свой `user_agent` в `config.yml` перебивает профиль: если поле отличается от встроенного значения по умолчанию, на провод уходит именно оно. `rustls` — контрольная форма: она никого не изображает и оставляет заголовки и преамбулу HTTP/2 такими, какими их отправляли все прошлые измерения.

Проверка на `tls.peet.ws`: JA3/JA4, `User-Agent`, набор и порядок заголовков, `SETTINGS` и `WINDOW_UPDATE` совпадают с `curl_chrome107` в точности; `peetprint` (он сворачивает в один хэш ещё и порядок псевдозаголовков с приоритетом) — нет.

---

## 🧩 Структура проекта

```text
crates/
├── dpi-core/          # движок: протоколы, зондирование, классификация
│   ├── classify/      #   DpiProbeStream и вердикты: код ОС/TLS + стадия -> DpiStatus
│   │                  #   detail.rs -- Detail: вердикт как значение, а не проза
│   ├── dns/           #   RFC 1035 wire, UDP, DoH, DoT, SOCKS5 UDP relay
│   ├── net/           #   TCP/TLS-примитивы (TlsProfile), отпечатки ClientHello
│   │                  #   (JA3/JA4, PQ), http_client, sysinfo (адаптеры, DNS)
│   ├── probe/         #   7 диагностических тестов и их общие примитивы
│   ├── config.rs      #   загрузка и нормализация config.yml
│   └── profile/       #   региональные профили цензуры (ru, ir, cn, global)
└── dpi-detector/      # CLI: аргументы, TUI, таблицы, машинный вывод
    ├── i18n/          #   все тексты интерфейса (En, Ru, Zh, Fa) + переводы detail
    ├── tui/           #   backend (VT/Win32), widgets (рамки, ширина, frame_repaint),
    │                  #   progress, input, screens/* (меню)
    ├── views/         #   по файлу на отчёт теста (banner, netinfo, dns, ..., summary)
    ├── json.rs        #   схема --json одним набором структур
    └── update.rs      #   проверка обновлений через GitHub Releases
```

Движок ничего не знает об интерфейсе: он возвращает типизированные отчёты,
`DpiStatus` и `Detail` с их машинными кодами, а тексты, таблицы и JSON собирает
бинарник.

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

Перед коммитом прогоняются обе проверки репозитория:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```
