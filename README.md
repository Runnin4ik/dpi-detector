<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>"Маяк у гаснущего горизонта свободного интернета"</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🔍 DPI Detector
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/Runnin4ik/dpi-detector/pkgs/container/dpi-detector)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0.svg?logo=telegram&logoColor=white)](https://t.me/DPI_detector)

Инструмент для анализа цензуры трафика в России: обнаруживает и классифицирует блокировки сайтов, хостингов и CDN (TCP16-20 блокировки), а также подмену DNS-запросов провайдером.

> <b>Инструмент был полезен? Поставь ⭐ в качестве "спасибо"!</b>  
> 🕊️ Заглядывайте в наш <a href="https://t.me/DPI_detector">телеграм чат</a>

## 📥 Скачать / Download

<div align="left">
<table>
    <thead align="left">
        <tr>
            <th>ОС / Платформа</th>
            <th>Готовые сборки</th>
        </tr>
    </thead>
    <tbody align="left">
        <tr>
            <td><b>🪟 Windows</b></td>
            <td>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_win10.exe"><img src="https://img.shields.io/badge/Windows_10_/_11-x64-0078d7.svg?logo=windows&logoColor=white" alt="Windows 10/11"></a>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_win7.exe"><img src="https://img.shields.io/badge/Windows_7_/_8-Legacy-00a4ef.svg?logo=windows&logoColor=white" alt="Windows 7/8"></a>
            </td>
        </tr>
        <tr>
            <td><b>🐧 Linux</b></td>
            <td>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_x86_64"><img src="https://img.shields.io/badge/Linux-x86__64-f84e29.svg?logo=linux&logoColor=white" alt="Linux x86_64"></a>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_arm64"><img src="https://img.shields.io/badge/Linux-ARM64-168039.svg?logo=linux&logoColor=white" alt="Linux ARM64"></a>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_armv7"><img src="https://img.shields.io/badge/Linux-ARMv7-45bf55.svg?logo=linux&logoColor=white" alt="Linux ARMv7"></a>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_x86"><img src="https://img.shields.io/badge/Linux-x86_32bit-FF9966.svg?logo=linux&logoColor=white" alt="Linux x86"></a>
            </td>
        </tr>
        <tr>
            <td><b>🍎 macOS</b></td>
            <td>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_macos_arm64"><img src="https://img.shields.io/badge/Apple_Silicon-M1--M4-000000.svg?logo=apple&logoColor=white" alt="macOS Apple Silicon"></a>
                <a href="https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_macos_intel"><img src="https://img.shields.io/badge/Intel-x86__64-555555.svg?logo=apple&logoColor=white" alt="macOS Intel"></a>
            </td>
        </tr>
        <tr>
            <td><b>📱 Android (Termux)</b></td>
            <td>
                <a href="#-android-termux">Инструкция</a>
            </td>
        </tr>
        <tr>
            <td><b>🐳 Docker</b></td>
            <td>
                <a href="#-docker">Инструкция</a>
            </td>
        </tr>
    </tbody>
</table>
</div>

![Пример результатов](https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/screenshot.png)

## 🎯 Возможности

- **TCP 16-20KB блокировка** — обнаруживает обрыв соединения к CDN и хостингам после передачи 14-34KB
- **Подбор белых SNI для AS хостингов/CDN**
- **Проверка доступности заблокированных сайтов** — тестирует TLS 1.2, TLS 1.3 и HTTP
- **Проверка DNS** — выявляет перехват UDP/53, подмену IP-адресов заглушками и блокировку DoH/DoT
- **Классификация ошибок** — различает TCP RST, Connection Abort,
  Handshake/Read Timeout, TLS MITM, SNI-блокировку и другие
- **Гибкая настройка** — таймауты, свои списки доменов, DNS-серверы,
  выбор IPv4/IPv6 и конкурентности (1/5/20/50/100) прямо в меню

> [!WARNING]  
> Если у вас запущены средства обхода блокировок (например, zapret или GoodbyeDPI), результаты тестов будут искажены. Чтобы узнать реальное состояние фильтров вашего провайдера, выключите их перед началом проверки или убедитесь, что они работают в режиме обработки всех пакетов (режим ALL), а не только по списку.

## 🐋 Docker

### Быстрый старт
Docker проверит наличие обновлений и скачает свежую версию перед запуском
```bash
docker run --rm -it --pull=always ghcr.io/runnin4ik/dpi-detector:latest
```

### Web-интерфейс
```bash
docker run -d --name dpi-detector-web -p 7681:7681 --restart unless-stopped ghcr.io/runnin4ik/dpi-detector:web
```
Откройте в браузере: **`http://<IP_сервера>:7681`** или **`http://localhost:7681`**

## 🐍 Python 3.8+
**Требования:** httpx[socks,http2]>=0.28.1, rich>=14.3.2, PyYAML>=6.0.3

**Установка:**
```bash
# скачайте и распакуйте архив руками, или:
git clone https://github.com/Runnin4ik/dpi-detector.git
cd dpi-detector
python -m pip install -r requirements.txt
```

**Запуск:**
```bash
python dpi_detector.py
# или с параметрами
python dpi_detector.py -t 2 -d discord.com -p socks5://127.0.0.1:1080
```

## 🪟 Windows

Быстрое скачивание и запуск в PowerShell одной командой:
```powershell
curl.exe -fL -o dpi_detector.exe https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_win10.exe; if ($LASTEXITCODE -eq 0) { .\dpi_detector.exe }
```
*Либо скачайте `.exe` файл из [таблицы выше](#-скачать--download) и запустите двойным кликом.*

## 🐧 Linux

Быстрое скачивание и запуск одной командой:

**x86_64 (AMD / Intel):**
```bash
curl -fsSLO https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_x86_64 && chmod +x dpi_detector_v4.0.13_linux_x86_64 && ./dpi_detector_v4.0.13_linux_x86_64
```

**ARM64 (Raspberry Pi 3–5, Orange Pi, ARM VPS):**
```bash
curl -fsSLO https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_linux_arm64 && chmod +x dpi_detector_v4.0.13_linux_arm64 && ./dpi_detector_v4.0.13_linux_arm64
```

## 🍎 macOS

Быстрое скачивание и запуск одной командой (со снятием карантина):

**Apple Silicon (M1–M4):**
```bash
curl -fsSLO https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_macos_arm64 && chmod +x dpi_detector_v4.0.13_macos_arm64 && xattr -cr dpi_detector_v4.0.13_macos_arm64 && ./dpi_detector_v4.0.13_macos_arm64
```

**Intel:**
```bash
curl -fsSLO https://github.com/Runnin4ik/dpi-detector/releases/download/v4.0.13/dpi_detector_v4.0.13_macos_intel && chmod +x dpi_detector_v4.0.13_macos_intel && xattr -cr dpi_detector_v4.0.13_macos_intel && ./dpi_detector_v4.0.13_macos_intel
```
*(Приложение не нотаризовано: `xattr -cr` снимает системный карантин macOS на запуск)*

## 📱 Android (Termux)

Для запуска требуется терминал **Termux**.  
> ⚠️ Устанавливайте Termux только из **[F-Droid](https://f-droid.org/packages/com.termux/)** или **[GitHub Releases](https://github.com/termux/termux-app/releases)** (версия из Google Play устарела и не поддерживается).

#### Установка и запуск

```bash
pkg update && pkg upgrade -y
```
*(Если при обновлении спросит \[default=N\] — просто нажимайте Enter)*

```bash
pkg install git python clang make -y
```

```bash
git clone https://github.com/Runnin4ik/dpi-detector.git && cd dpi-detector
```

```bash
pip install -r requirements.txt
```

Перед запустом переведите телефон в горизонтальный режим!
```bash
python dpi_detector.py
```

### ⚙️ Кастомизация
Вы можете переопределить стандартные файлы и списки:

1. `domains.txt` — список доменов для проверки доступности (HTTP, TLS 1.2, TLS 1.3).
2. `tcp16.json` — цели и порты для теста TCP 16-20KB блокировок.
3. `config.yml` — параметры конфигурации (таймауты, DoH-серверы и т.д.).
4. `whitelist_sni.txt` — список белых SNI для подбора рабочих доменов.

- **Для готовых сборок (.exe / Linux / macOS):** скачайте нужные файлы из репозитория в папку рядом с исполняемым файлом и измените их.
- **Для Docker:** Запустите с монтированием (можно монтировать один или несколько файлов)

<details>
<summary><b>Команды монтирования для разных ОС (Нажмите чтобы открыть)</b></summary>

```bash
# Bash (Linux / macOS)
docker run --rm -it --pull=always \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp16.json:/app/tcp16.json \
  -v $(pwd)/config.yml:/app/config.yml \
  -v $(pwd)/whitelist_sni.txt:/app/whitelist_sni.txt \
  ghcr.io/runnin4ik/dpi-detector:latest -t 123 -d discord.com
```

PowerShell (Windows)
```bash
docker run --rm -it --pull=always `
  -v ${PWD}/domains.txt:/app/domains.txt `
  -v ${PWD}/tcp16.json:/app/tcp16.json `
  -v ${PWD}/config.yml:/app/config.yml `
  -v ${PWD}/whitelist_sni.txt:/app/whitelist_sni.txt `
  ghcr.io/runnin4ik/dpi-detector:latest
```

CMD (Windows)
```bash
docker run --rm -it --pull=always ^
  -v %cd%/domains.txt:/app/domains.txt ^
  -v %cd%/tcp16.json:/app/tcp16.json ^
  -v %cd%/config.yml:/app/config.yml ^
  -v %cd%/whitelist_sni.txt:/app/whitelist_sni.txt ^
  ghcr.io/runnin4ik/dpi-detector:latest
```

Docker с Web интерфейсом:
```bash
docker run -d --name dpi-detector-web -p 7681:7681 \
  -v $(pwd)/config.yml:/app/config.yml \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/whitelist_sni.txt:/app/whitelist_sni.txt \
  --restart unless-stopped \
  ghcr.io/runnin4ik/dpi-detector:web
```

Либо через Docker Compose в скачанной папке проекта:
```bash
docker compose up -d
```
</details>


### ⚙️ Запуск с параметрами (CLI)

| Параметр              | Описание                                                            | Пример использования         |
|:----------------------|:--------------------------------------------------------------------|:-----------------------------|
| `-t`, `--tests`       | Указать номера тестов (без меню).                                   | `-t 123` или `-t 4`          |
| `-p`, `--proxy`       | Использовать прокси (переопределяет `PROXY_URL`).                   | `-p socks5://127.0.0.1:1080` |
| `-d`, `--domain`      | Проверка отдельных доменов. Игнорирует `domains.txt`                | `-d vk.com -d youtube.com`   |
| `-c`, `--concurrency` | Количество конкурентных запросов (переопределяет `MAX_CONCURRENT`). | `-c 50`                      |
| `-o`, `--output`      | Автоматически сохранить лог в указанный файл.                       | `-o report_log.txt`          |
| `--batch`             | Отключает все вопросы и паузы в консоли.                            | `--batch`                    |
| `--update`            | Проверить и обновить до последней версии, затем выйти.              | `--update`                   |

> **Параметры работают и для готовых бинарников** (`.exe` / Linux / macOS) — они принимают те же флаги, что и запуск из исходников `python dpi_detector.py`.

### Примеры запуска

#### Из исходников (Python)
```bash
python dpi_detector.py -t 0 --batch
```

#### Бинарник (любой)
```bash
./dpi_detector_v4.0.13_linux_x86_64 -t 0 --batch
```

> **Прокси:** при заданном `PROXY_URL`/`-p` весь трафик всех тестов идёт через прокси,
> включая UDP-пробы теста 1 (через SOCKS5 UDP-relay; для HTTP-прокси UDP-релей невозможен —
> UDP-пробы идут напрямую). Для честного замера подмены своим провайдером запускайте без прокси.

## 🤝 Вклад в проект
Приветствуются Issue и Pull Request'ы и предложения функционала!

## 📜 Лицензия

[MIT License](LICENSE) — свободное использование, модификация и распространение.

## ⚠️ Дисклеймер

Этот инструмент предназначен исключительно для образовательных и диагностических целей. Автор не несет ответственности за использование данного ПО.

## 🙏 Благодарности

- Проекту [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) за вдохновение
- **0ka** за помощь и консультации

## 👀Похожие проекты
Советуем также взглянуть:
- [hyperion-cs/dpi-ch](https://github.com/hyperion-cs/dpi-checkers/tree/main/ru/dpi-ch) — _DPI comprehensive checker (go)_

## 💖 Поддержка проекта

### [Картой или по СБП](https://pay.cloudtips.ru/p/1421d4c7)

| Валюта   | Сеть   | Адрес                                              |
|----------|--------|----------------------------------------------------|
| **USDT** | TRC20  | `TGtcb4JMT5F3KiEL16oZnj9ijB2Pag1jCX`               |
| **USDT** | ERC20  | `0x97413028546b5da4cbba4d9838c9d635a5333ab1`       |
| **USDT** | TON    | `UQApgV57_p0hQGBV9oxrDi7SvKqgN3pigw5YEA28VShrZ7X_` |
| **TON**  |        | `UQApgV57_p0hQGBV9oxrDi7SvKqgN3pigw5YEA28VShrZ7X_` |
| **BNB**  | BEP-20 | `0x97413028546b5da4cbba4d9838c9d635a5333ab1`       |
| **SOL**  |        | `9obMiD8hYfs4D8XskQjHPPtAKYPq9CaEZTbBMxtCjQ3k`     |
| **BTC**  |        | `bc1q7579xpmxcrz34lzmrxfupkpcczvemeqk2e9f4h`       |
| **ETH**  |        | `0x97413028546b5da4cbba4d9838c9d635a5333ab1`       |
