import sys
import json
from pathlib import Path
from typing import List, Any

from cli.console import console

def wait_and_exit(code: int = 1):
    is_interactive = sys.stdin.isatty() and "--batch" not in sys.argv
    if is_interactive:
        print("\nНажмите любую клавишу для выхода...")
        try:
            import msvcrt
            msvcrt.getch()
        except (ImportError, OSError):
            try:
                input()
            except (EOFError, OSError):
                pass
    sys.exit(code)

def get_base_dir() -> Path:
    """Возвращает путь к директории запуска (рядом с .exe или корнем проекта)."""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    # __file__ находится в utils/files.py, поднимаемся на 2 уровня вверх к корню
    return Path(__file__).resolve().parent.parent

def get_resource_path(relative_path: str) -> Path:
    """Ищет файл сначала снаружи, затем во внутреннем бандле PyInstaller."""
    base_dir = get_base_dir()
    external_path = base_dir / relative_path

    if external_path.exists():
        return external_path

    # Если запущено из-под PyInstaller, проверяем временную папку _MEIPASS
    if hasattr(sys, '_MEIPASS'):
        bundled_path = Path(sys._MEIPASS) / relative_path
        if bundled_path.exists():
            return bundled_path

    return external_path

def load_domains(filepath: str = "domains.txt", raise_on_error: bool = False) -> List[str]:
    """Загружает список доменов из файла."""
    path = get_resource_path(filepath)

    if not path.exists():
        if raise_on_error:
            raise FileNotFoundError(f"Файл {filepath} не найден: {path}")
        console.print("[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {path}[/red]")
        console.print(f"[yellow]Положите {filepath} рядом с программой.[/yellow]")
        wait_and_exit()

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [
                line.strip() for line in f
                if line.strip() and not line.startswith('#')
            ]
    except Exception as e:
        if raise_on_error:
            raise
        console.print(f"[bold red]Ошибка чтения файла {filepath}: {e}[/bold red]")
        wait_and_exit()
def load_tcp_targets(filepath: str = "tcp16.json", raise_on_error: bool = False) -> List[Any]:
    """Загружает JSON с целями для TCP теста."""
    path = get_resource_path(filepath)

    if not path.exists():
        if raise_on_error:
            raise FileNotFoundError(f"Файл {filepath} не найден: {path}")
        console.print("[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {path}[/red]")
        wait_and_exit()

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"Ожидался JSON-список, получен {type(data).__name__}")
        return [item for item in data if isinstance(item, dict) and "ip" in item]
    except json.JSONDecodeError as e:
        if raise_on_error:
            raise
        console.print(f"[bold red]ОШИБКА: Некорректный JSON в {filepath}![/bold red]")
        console.print(f"[red]{e}[/red]")
        wait_and_exit()
    except Exception as e:
        if raise_on_error:
            raise
        console.print(f"[bold red]Ошибка чтения {filepath}: {e}[/bold red]")
        wait_and_exit()
def load_whitelist_sni(filepath: str = "whitelist_sni.txt") -> list:
    """Загружает список SNI для белого списка из файла."""
    path = get_resource_path(filepath)

    if not path.exists():
        console.print(f"[yellow]Файл {filepath} не найден, тест 4 недоступен.[/yellow]")
        return []

    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [
                line.strip() for line in f
                if line.strip() and not line.strip().startswith('#')
            ]
    except Exception as e:
        console.print(f"[yellow]Ошибка чтения {filepath}: {e}[/yellow]")
        return []
