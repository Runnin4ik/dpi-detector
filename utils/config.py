import os
import sys

try:
    import yaml
except ImportError:
    print("[!] Ошибка: Не установлена библиотека PyYAML.")
    print("Установите зависимости: pip install -r requirements.txt")
    sys.exit(1)

from pathlib import Path

def load_config():
    if getattr(sys, 'frozen', False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).resolve().parent.parent

    yml_path = base_dir / "config.yml"

    if not yml_path.exists():
        print(f"[!] КРИТИЧЕСКАЯ ОШИБКА: Файл конфигурации не найден!")
        print(f"Ожидаемый путь: {yml_path}")
        input("Нажмите Enter для выхода...")
        sys.exit(1)

    try:
        with open(yml_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)

        if not isinstance(config_data, dict):
            raise ValueError("Файл config.yml пуст или имеет неверный формат.")

        for key, value in config_data.items():
            if key.isupper():
                globals()[key] = value

    except Exception as e:
        print(f"[!] КРИТИЧЕСКАЯ ОШИБКА при чтении config.yml:")
        print(f"{e}")
        input("Нажмите Enter для выхода...")
        sys.exit(1)

load_config()