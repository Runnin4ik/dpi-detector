"""Отображение шапки, баннера и проверка обновлений приложения."""

from typing import Optional, Tuple
import asyncio
import httpx
from rich.panel import Panel
from rich import box

from cli.ui import BOX_W
from utils import config
from utils.version import is_newer

CURRENT_VERSION = "4.2.4"
GITHUB_REPO     = "Runnin4ik/dpi-detector"


def render_banner(badge: str = "Проверка обновлений...") -> Tuple[Panel, int]:
    """Баннер: Panel со стилями Rich Markup (заголовок, автор, GitHub, чат, обновления)."""
    if badge == "✓ Актуальная версия":
        badge_colored = "[#5af78e]✓ Актуальная версия[/#5af78e]"
    elif badge.startswith("↑"):
        badge_colored = f"[yellow]{badge}[/yellow]"
    elif badge.startswith("×"):
        badge_colored = f"[dim]{badge}[/dim]"
    else:
        badge_colored = f"[dim]{badge}[/dim]"

    row1 = "  [dim]Автор:[/dim] [rgb(214,180,255)]Runni[/rgb(214,180,255)] [cyan]•[/cyan] [dim]GitHub:[/dim] Runnin4ik/dpi-detector"
    row2 = f"  [dim]Чат:[/dim] t.me/DPI_detector [cyan]•[/cyan] {badge_colored}"
    panel = Panel(
        f"{row1}\n{row2}",
        title=f"DPI Detector v{CURRENT_VERSION}",
        title_align="left",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
        width=BOX_W,
    )
    return panel, 4


def version_badge(latest: Optional[dict]) -> str:
    """Бейдж статуса обновлений для баннера."""
    if not latest:
        return "× Не удалось проверить обновления"
    version = latest.get("version") or ""
    if version and is_newer(version, CURRENT_VERSION):
        return f"↑ Доступна новая версия {version}"
    return "✓ Актуальная версия"


def header_render(header: dict):
    """Шапка: баннер (со статусом обновлений)."""
    return header.get("banner")


def header_height(header: dict) -> int:
    return header.get("banner_lines", 0)


async def fetch_latest_version() -> Optional[dict]:
    """Последний релиз: {'tag': 'v4.0.X', 'version': '4.0.X'} или None."""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    proxy_url = getattr(config, "PROXY_URL", None)
    try:
        async with httpx.AsyncClient(timeout=3.0, proxy=proxy_url, trust_env=False) as client:
            resp = await client.get(url, headers={"Accept": "application/vnd.github+json"})
            if resp.status_code == 200:
                data = resp.json()
                tag = data.get("tag_name", "")
                if not tag:
                    return None
                return {
                    "tag": tag,
                    "version": tag.lstrip("v"),
                }
    except Exception:
        pass
    return None


def init_header_state() -> Tuple[dict, asyncio.Task]:
    """Создаёт начальное состояние шапки и фоновую задачу обновления версии."""
    banner, banner_lines = render_banner()
    header = {
        "banner": banner,
        "banner_lines": banner_lines,
        "latest": None,
        "current": CURRENT_VERSION,
    }
    version_task = asyncio.create_task(fetch_latest_version())

    async def _update_banner_badge() -> None:
        try:
            latest = await asyncio.wait_for(asyncio.shield(version_task), timeout=4.0)
        except Exception:
            latest = None
        header["latest"] = latest
        b, b_lines = render_banner(version_badge(latest))
        header["banner"], header["banner_lines"] = b, b_lines

    ver_task = asyncio.create_task(_update_banner_badge())
    return header, ver_task
