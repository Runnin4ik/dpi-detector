"""Авто-обновление приложения: git-клон / бинарник / Docker / source.

Точка входа — `perform_update(latest, current_version)`, вызывается из меню
(пункт «Обновить до vX.Y.Z»). Обновление НЕ автоматическое — только по
выбору пользователя. Docker: автообновление отключено (подсказка pull).
"""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import httpx

from cli.console import console
from utils import config
from utils.files import get_base_dir

GITHUB_REPO = "Runnin4ik/dpi-detector"


def is_newer(latest: str, current: str) -> bool:
    """Semver-сравнение: latest > current. Устойчив к 'v' и мусору."""
    try:
        def parse(v: str) -> tuple:
            return tuple(int(x) for x in v.replace('v', '').split('.') if x.isdigit())
        return parse(latest) > parse(current)
    except Exception:
        return False


def get_launch_type() -> str:
    """Как запущена программа: docker | binary | git | source."""
    if os.path.exists("/.dockerenv") or os.environ.get("container"):
        return "docker"
    if getattr(sys, "frozen", False):
        return "binary"
    if (get_base_dir() / ".git").exists():
        return "git"
    return "source"


def detect_suffix() -> str:
    """Суффикс имени ассета релиза для текущей платформы
    (win10/win7/linux_x86_64/linux_arm64/linux_armv7/linux_x86/macos_arm64/macos_intel)."""
    if sys.platform == "win32":
        try:
            ver = sys.getwindowsversion()
            return "win7" if ver.major <= 6 else "win10"
        except Exception:
            return "win10"
    machine = platform.machine().lower()
    if sys.platform == "darwin":
        return "macos_arm64" if machine in ("arm64", "aarch64") else "macos_intel"
    if machine in ("x86_64", "amd64"):
        return "linux_x86_64"
    if machine in ("aarch64", "arm64"):
        return "linux_arm64"
    if machine.startswith("arm"):
        return "linux_armv7"
    if machine in ("i386", "i686", "x86"):
        return "linux_x86"
    return "linux_x86_64"


def cleanup_old_binaries(current_version: str) -> None:
    """Удаляет рядом с текущим бинарником файлы dpi_detector_*_{suffix}
    старее current_version (версионные имена копятся при обновлениях).
    Запущенный файл не трогаем (он и есть current_version)."""
    if not getattr(sys, "frozen", False):
        return
    suffix = detect_suffix()
    pattern = re.compile(rf"^dpi_detector_v([\d.]+)_{re.escape(suffix)}(\.exe)?$")
    for f in get_base_dir().glob(f"dpi_detector_*_{suffix}*"):
        m = pattern.match(f.name)
        if not m:
            continue
        if is_newer(current_version, m.group(1)):
            try:
                f.unlink()
            except OSError:
                pass


def _execv(argv: list) -> None:
    """Перезапуск процесса. Убирает --update из аргументов: после обновления
    перезапущенный экземпляр не должен снова входить в CLI-обновление."""
    if "--update" in argv:
        argv = [a for a in argv if a != "--update"]
    os.execv(argv[0], argv)


async def _download(url: str, dest: Path, expected_sha: Optional[str] = None) -> bool:
    """Скачивает файл в dest (рядом с ним), при expected_sha сверяет SHA-256
    ДО финального переименования. Возвращает True при успехе."""
    proxy_url = getattr(config, "PROXY_URL", None)
    tmp = dest.with_name(dest.name + ".part")
    try:
        async with httpx.AsyncClient(timeout=60.0, proxy=proxy_url,
                                     trust_env=False, follow_redirects=True) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    console.print(f"[red]Ошибка загрузки: HTTP {resp.status_code}[/red]")
                    return False
                sha = hashlib.sha256()
                with console.status(f"Скачивание {dest.name}...", spinner="line"):
                    with open(tmp, "wb") as f:
                        async for chunk in resp.aiter_bytes():
                            f.write(chunk)
                            sha.update(chunk)
        if expected_sha and sha.hexdigest().lower() != expected_sha.lower():
            console.print(
                "[red]Ошибка: SHA-256 не совпадает — файл повреждён или подменён.[/red]"
                "\n[yellow]Обновление отменено, текущая версия не тронута.[/yellow]"
            )
            try:
                tmp.unlink()
            except OSError:
                pass
            return False
        os.replace(tmp, dest)
        return True
    except Exception as e:
        console.print(f"[red]Ошибка загрузки: {e}[/red]")
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


async def _update_git() -> bool:
    """Обновление git-клона (Termux / Linux): бэкап конфигов, pull, pip, execv."""
    base = get_base_dir()
    for name in ("config.yml", "domains.txt", "tcp16.json", "whitelist_sni.txt"):
        src = base / name
        if src.exists() and not (base / (name + ".bak")).exists():
            try:
                shutil.copy2(src, base / (name + ".bak"))
            except Exception:
                pass
    try:
        r = subprocess.run(["git", "pull", "--ff-only"], cwd=str(base),
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            console.print(f"[red]git pull не удался:[/red] {r.stderr.strip() or r.stdout.strip()}")
            return False
    except Exception as e:
        console.print(f"[red]git pull не удался: {e}[/red]")
        return False
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r",
             str(base / "requirements.txt"), "--upgrade"],
            check=True, capture_output=True, text=True, timeout=300)
    except Exception as e:
        console.print(f"[yellow]pip install: {e}[/yellow]")
    console.print("[green]Обновлено! Перезапуск...[/green]")
    _execv([sys.executable] + sys.argv)
    return True


def _macos_cleanup(path: Path) -> None:
    """Снимает quarantine и переподписывает ad-hoc после замены бинарника."""
    for cmd in (["xattr", "-cr", str(path)],
                ["codesign", "--force", "-s", "-", str(path)]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
        except Exception:
            pass


async def _update_binary(latest: dict) -> bool:
    """Обновление собранного бинарника (PyInstaller)."""
    tag = (latest.get("tag") or "").lstrip("v")
    version = latest.get("version") or ""
    assets = latest.get("assets") or []
    suffix = detect_suffix()
    asset_name = f"dpi_detector_v{tag}_{suffix}" + (".exe" if sys.platform == "win32" else "")
    # assets: [{'name': ..., 'digest': 'sha256:...'}] — digest отдаёт GitHub API
    asset = next((a for a in assets
                  if isinstance(a, dict) and a.get("name") == asset_name), None)
    if asset is None:
        console.print(f"[yellow]Ассет {asset_name} не найден в релизе v{tag}.[/yellow]")
        return False
    digest = asset.get("digest") or ""
    expected = digest.split(":", 1)[1] if digest.startswith("sha256:") else None
    if not expected:
        console.print("[yellow]SHA-256 недоступен для ассета в релизе — обновление отменено.[/yellow]")
        return False

    url = f"https://github.com/{GITHUB_REPO}/releases/download/v{tag}/{asset_name}"
    console.print(f"[cyan]Скачивание v{version}...[/cyan]")
    base = get_base_dir()
    dest = base / asset_name
    if not await _download(url, dest, expected):
        return False

    if sys.platform == "win32":
        # Имя версионное — новый файл рядом не конфликтует с запущенным exe.
        # Старые версии уберёт cleanup_old_binaries при следующем старте.
        console.print("[green]Новая версия скачана. Перезапуск...[/green]")
        _execv([str(dest)] + sys.argv[1:])
        return True

    # POSIX: атомарная замена текущего бинарника (можно поверх запущенного)
    current = Path(sys.executable)
    bak = current.with_name(current.name + ".bak")
    try:
        shutil.copy2(current, bak)
    except Exception:
        pass
    os.chmod(dest, 0o755)
    os.replace(dest, current)
    if sys.platform == "darwin":
        _macos_cleanup(current)
    console.print("[green]Обновлено! Перезапуск...[/green]")
    _execv([str(current)] + sys.argv[1:])
    return True


async def perform_update(latest: Optional[dict], current_version: str) -> bool:
    """Запускает обновление по типу окружения. Возвращает True, если
    обновление выполнено (процесс, как правило, перезапускается через execv)."""
    if not latest:
        console.print("[yellow]Не удалось получить данные о последней версии.[/yellow]")
        return False
    launch = get_launch_type()
    if launch == "docker":
        console.print("[yellow]Вы используете Docker. Обновите образ:[/yellow] "
                      "[cyan]docker pull ghcr.io/runnin4ik/dpi-detector:latest[/cyan]")
        return False
    if launch == "git":
        return await _update_git()
    if launch == "binary":
        return await _update_binary(latest)
    console.print("[yellow]Автообновление недоступно для этой установки "
                  "(запуск из архива без git).[/yellow]\n"
                  f"[cyan]Скачайте вручную: https://github.com/{GITHUB_REPO}/releases[/cyan]")
    return False
