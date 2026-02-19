# 🔍 DPI Detector

Инструмент для обнаружения блокировок сайтов/CDN/хостинг-провайдеров у российских интернет-провайдеров.

> ⭐ Если проект полезен, поставьте звезду!

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/Runnin4ik/dpi-detector/pkgs/container/dpi-detector)

![Пример результатов](https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/screenshot.png)

## 🎯 Возможности

- ✅ **Анализ TLS** - Проверка работы TLS 1.2 и TLS 1.3, обнаружение подмены сертификатов (MITM) и блокировки по SNI
- ✅ **HTTP Injection детектор** - находит редиректы на блок-страницы провайдера
- ✅ **TCP 16-20KB блокировка** - обнаруживает обрыв соединения после передачи 14-34KB
- ✅ **Классификация ошибок** - TCP Reset (RST), Connection Abort, Handshake/Read Timeout, TLS alerts, SNI blocking, MITM (подмена сертификата), HTTP 451 и редиректы провайдера.
- ✅ **Поддержка IPv4-only режима** - для изоляции от IPv6

## 🐋 Docker (Рекомендовано)

### Быстрый старт
Docker проверит наличие обновлений и скачает свежую версию перед запуском
```bash
docker run --rm -it --pull=always ghcr.io/runnin4ik/dpi-detector:latest
```
Или запускайте с указанием определенной версии  
Это избавляет от постоянных скачиваний, но нужно следить за актуальностью версий
```bash
docker run --rm -it ghcr.io/runnin4ik/dpi-detector:1.3
```

#### С кастомными доменами
Создайте нужные кастомные файлы: `domains.txt`, `tcp_16_20_targets.json` или `config.py`  
Запустите с монтированием (можно монтировать один или несколько файлов)
```bash
# Bash (Linux / macOS)
docker run --rm -it \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/tcp_16_20_targets.json:/app/tcp_16_20_targets.json \
  -v $(pwd)/config.py:/app/config.py \
  ghcr.io/runnin4ik/dpi-detector:latest
```
<details>
<summary>Команды для PowerShell и CMD</summary>

PowerShell (Windows)
```bash
docker run --rm -it `
  -v ${PWD}/domains.txt:/app/domains.txt `
  -v ${PWD}/tcp_16_20_targets.json:/app/tcp_16_20_targets.json `
  -v ${PWD}/config.py:/app/config.py `
  ghcr.io/runnin4ik/dpi-detector:latest
```

CMD (Windows)
```bash
docker run --rm -it ^
  -v %cd%/domains.txt:/app/domains.txt ^
  -v %cd%/tcp_16_20_targets.json:/app/tcp_16_20_targets.json ^
  -v %cd%/config.py:/app/config.py ^
  ghcr.io/runnin4ik/dpi-detector:latest
```
</details>

## 🐍 Python 3.10+
**Требования:** httpx>=0.28, rich>=14.3, aiodns>=4.0

**Установка:**
```bash
git clone https://github.com/Runnin4ik/dpi-detector.git
cd dpi-detector
python -m pip install -r requirements.txt
```

**Запуск:**
```bash
python dpi_detector.py
```

## 🪟 Windows
Для тех, кто не хочет ставить python - к каждому релизу прикреплен [.exe файл](https://github.com/Runnin4ik/dpi-detector/releases/download/v1.3.0/dpi_detector_v1_3.exe)  

Также вы можете переопределить файлы `domains.txt`, `tcp_16_20_targets.json` или `config.py`  
Положив их рядом с `.exe` файлом  

## Кастомизация:
```bash
# Домены для проверки блокировки/замедления
domains.txt
# Домены для проверки TCP 16-20KB блокировки
tcp_16_20_targets.json
# Много настроек, которые можно менять
config.py
```

## 🤝 Вклад в проект
Приветствуются Issue и Pull Request'ы и предложения функционала!

## 📜 Лицензия

[MIT License](LICENSE) — свободное использование, модификация и распространение.

## ⚠️ Дисклеймер

Этот инструмент предназначен исключительно для образовательных и диагностических целей. Автор не несет ответственности за использование данного ПО.

## 🙏 Благодарности

- Вдохновлено проектом [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) и частично используются его домены для проверки TCP16-20 блокировок