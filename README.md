<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>«Маяк у гаснущего горизонта свободного интернета»</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🔍 DPI Detector
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/Runnin4ik/dpi-detector/pkgs/container/dpi-detector)

Инструмент для анализа цензуры трафика в России: обнаруживает и классифицирует блокировки сайтов, хостингов и CDN (TCP16-20 блокировки), а также подмену DNS-запросов провайдером.

> <b>Инструмент был полезен? Поставь ⭐ в качестве «спасибо»!</b>

![Пример результатов](https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/screenshot.png)

## 🎯 Возможности

- **TCP 16-20KB блокировка** — обнаруживает обрыв соединения к CDN и хостингам после передачи 14-34KB
- **Подбор белых SNI для AS хостингов/CDN**
- **Проверка доступности заблокированных сайтов** — тестирует TLS 1.2, TLS 1.3 и HTTP
- **Проверка DNS** — выявляет перехват UDP/53, подмену IP-адресов заглушками и блокировку DoH
- **Классификация ошибок** — различает TCP RST, Connection Abort,
  Handshake/Read Timeout, TLS MITM, SNI-блокировку и другие
- **Гибкая настройка** — таймауты, потоки, свои списки доменов, DNS-серверы
  и IPv4-only режим

> [!WARNING]  
> Если у вас запущены средства обхода блокировок (например, zapret или GoodbyeDPI), результаты тестов будут искажены. Чтобы узнать реальное состояние фильтров вашего провайдера, выключите их перед началом проверки или убедитесь, что они работают в режиме обработки всех пакетов (режим ALL), а не только по списку.

### ⚙️ Кастомизация
Следующие файлы могут быть переопределены. Инструкции ниже.

1.  `domains.txt` — список доменов для проверки.
2.  `tcp16.json` — цели для теста TCP 16-20KB.
3.  `config.yml` — конфигурация.
4.  `whitelist_sni.txt` — список белых SNI для подбора рабочих

### ⚙️ Запуск с параметрами (CLI)

| Параметр              | Описание                                                            | Пример использования         |
|:----------------------|:--------------------------------------------------------------------|:-----------------------------|
| `-t`, `--tests`       | Указать номера тестов (без меню).                                   | `-t 123` или `-t 4`          |
| `-p`, `--proxy`       | Использовать прокси (переопределяет `PROXY_URL`).                   | `-p socks5://127.0.0.1:1080` |
| `-d`, `--domain`      | Проверка отдельных доменов. Игнорирует `domains.txt`                | `-d vk.com -d youtube.com`   |
| `-c`, `--concurrency` | Количество конкурентных запросов (переопределяет `MAX_CONCURRENT`). | `-c 50`                      |
| `-o`, `--output`      | Автоматически сохранить лог в указанный файл.                       | `-o report_log.txt`          |
| `--batch`             | Отключает все вопросы и паузы в консоли.                            | `--batch`                    |

## 🐋 Docker (Рекомендовано)

### Быстрый старт
Docker проверит наличие обновлений и скачает свежую версию перед запуском
```bash
docker run --rm -it --pull=always ghcr.io/runnin4ik/dpi-detector:latest
```
Или запускайте с указанием определенной версии  
Это избавляет от постоянных скачиваний, но нужно следить за актуальностью версий
```bash
docker run --rm -it ghcr.io/runnin4ik/dpi-detector:3.2.2
```

#### С кастомизацией
Переопределите нужные файлы: `domains.txt`, `tcp16.json`...
Запустите с монтированием (можно монтировать один или несколько файлов)
```bash
# Bash (Linux / macOS)
docker run --rm -it --pull=always \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp16.json:/app/tcp16.json \
  -v $(pwd)/config.yml:/app/config.yml \
  -v $(pwd)/whitelist_sni.txt:/app/whitelist_sni.txt \
  ghcr.io/runnin4ik/dpi-detector:latest -t 123 -d discord.com
```
<details>
<summary>Команды для PowerShell и CMD</summary>

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
</details>

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

## 🪟 Windows (Готовые сборки)

Для использования программы не обязательно устанавливать Python. Скачайте подходящий `.exe` файл в разделе [Releases -> Assets](https://github.com/Runnin4ik/dpi-detector/releases):

*   **[Скачать для Windows 10 / 11](https://github.com/Runnin4ik/dpi-detector/releases/download/v3.2.2/dpi_detector_v3.2.2_win10.exe)**
*   **[Скачать для Windows 7 / 8](https://github.com/Runnin4ik/dpi-detector/releases/download/v3.2.2/dpi_detector_v3.2.2_win7.exe)**

#### С кастомизацией

Переопределите нужные файлы: `domains.txt`, `tcp16.json`, `config.yml`, `whitelist_sni.txt`
И положите их в папку рядом с `.exe` файлом.

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

## Star History

<a href="https://www.star-history.com/#Runnin4ik/dpi-detector&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=Runnin4ik/dpi-detector&type=date&legend=top-left" />
 </picture>
</a>