"""Интерактивные меню и выбор тестов."""

from typing import Optional
import asyncio
import sys
from rich.panel import Panel
from rich import box

from cli.console import console
from cli.ui import ask_test_selection, print_legend
from cli.input import _flush_stdin, _read_key_cancelable, _selection_flags
from app.banner import header_render

async def handle_legend_menu(selection: str) -> str:
    """Интерактивный цикл, если выбрана только легенда (6)."""
    while True:
        print_legend()
        if sys.stdin is None or not sys.stdin.isatty():
            return selection
        console.print(Panel(
            "[bold white not dim on dark_green]  Enter  [/] Повторить   "
            "[bold white not dim on dark_blue]  M  [/] Меню   "
            "[bold white not dim on dark_red]  Q  [/] Выход",
            style="dim", box=box.HORIZONTALS,
        ))
        _flush_stdin()
        try:
            key = await _read_key_cancelable()
        except KeyboardInterrupt:
            raise
        if key in ("m", "ь", "v", "м"):
            new_selection = await ask_test_selection()
            (_, _, _, _, _, _, _, only_legend) = _selection_flags(new_selection)
            if not only_legend:
                return new_selection
            console.print()
        elif key in ("q", "й"):
            raise SystemExit(0)


async def prompt_test_selection(
    header: dict,
    ver_task: asyncio.Task,
    cli_tests: Optional[str] = None,
) -> str:
    """Выбор тестов через интерактивное меню или ожидание версии при заданном --tests."""
    if cli_tests:
        try:
            await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
        except Exception:
            pass
        console.print(header_render(header))
        return cli_tests

    if sys.stdin is None or not sys.stdin.isatty():
        try:
            await asyncio.wait_for(asyncio.shield(ver_task), timeout=4.0)
        except Exception:
            pass
        console.print(header_render(header))

    return await ask_test_selection(header_state=header, version_task=ver_task)
