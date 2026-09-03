"""Обработка аргументов командной строки, проверка зависимостей и логирование."""

import sys
import argparse
import logging

from utils import config
from cli.console import console
from cli.ui import restore_terminal


def parse_arguments() -> argparse.Namespace:
    """Парсинг аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description="DPI Detector — Анализатор блокировок трафика",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--tests",       type=str, help="Список тестов для запуска (например: 123 или 24). Пропускает стартовое меню.")
    parser.add_argument("-p", "--proxy",       type=str, help="URL прокси (напр: socks5://127.0.0.1:1080) (PROXY_URL)")
    parser.add_argument("-c", "--concurrency", type=int, help="Максимальное количество параллельных запросов (MAX_CONCURRENT)")
    parser.add_argument("-d", "--domain",      type=str, action="append", help="Проверить конкретный домен(ы), игнорируя domains.txt.\nМожно указывать несколько раз: -d vk.com -d ya.ru")
    parser.add_argument("-o", "--output",      type=str, help="Путь для автосохранения отчета (например: report.txt).")
    parser.add_argument("--batch",             action="store_true", help="Отключает паузы и вопросы")
    parser.add_argument("-v", "--verbose",     action="store_true", help="Включить подробный вывод отладки (DEBUG логи)")
    args = parser.parse_args()
    if args.concurrency is not None and args.concurrency < 1:
        parser.error("Параметр --concurrency должен быть целым числом >= 1.")
    if args.tests:
        valid_chars = set("0123456")
        if not all(c in valid_chars for c in args.tests):
            parser.error(f"Недопустимое значение --tests: '{args.tests}'. Допустимы только цифры 0-6.")
    return args


def setup_logging(verbose: bool = False) -> None:
    """Настройка логирования: DEBUG при -v/--verbose или config.DEBUG, иначе WARNING."""
    level = logging.DEBUG if (verbose or getattr(config, "DEBUG", False)) else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def fast_exit_handler(sig=None, frame=None):
    console.print("\n[bold red]Прервано пользователем.[/bold red]")
    restore_terminal()
    sys.exit(0)


def check_dependencies(github_repo: str = "Runnin4ik/dpi-detector") -> None:
    """Проверка наличия всех runtime-зависимостей."""
    required = [
        ("h2", "h2 — HTTP/2 для DoH (pip install httpx[http2])"),
        ("socksio", "socksio — SOCKS-прокси (pip install httpx[socks])"),
        ("hpack", "hpack — HTTP/2 (ставится вместе с h2)"),
        ("yaml", "PyYAML (pip install pyyaml)"),
        ("rich", "rich (pip install rich)"),
    ]
    missing = []
    for mod, hint in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(hint)
    if missing:
        console.print("[bold red]Сборка неполная — отсутствуют модули:[/bold red]")
        for hint in missing:
            console.print(f"  [red]×[/red] {hint}")
        console.print("\n[bold yellow]Скачайте официальный релиз:[/bold yellow] "
                      f"[cyan]https://github.com/{github_repo}/releases[/cyan]")
        try:
            input("Enter для выхода...")
        except EOFError:
            pass
        sys.exit(1)
