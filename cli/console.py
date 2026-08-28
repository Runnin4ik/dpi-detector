"""Глобальная rich-консоль приложения.

На POSIX (WSL, Linux) stdout оборачивается в CRLF-врайтер: если терминал
оказывается LF-only (OPOST отключён или обёртка не переводит LF в CRLF),
все строки "лесенкой" уходят вправо. При перенаправлении в файл/пайп
(isatty() = False) вывод остаётся LF.
"""


import os
import sys

from rich.console import Console


def _enable_windows_vt() -> None:
    """Включает обработку ANSI/VT в консоли Windows (ENABLE_VIRTUAL_TERMINAL_PROCESSING).

    Rich включает этот флаг сам для своего вывода, но прямые sys.stdout.write()
    (banner, курсорные команды меню, тест 0) идут в обход Rich. Без флага старый
    conhost (cmd, Windows 10/Server 2022) печатает ESC-последовательности как
    текст (←[0J, ←[36m...), и интерфейс двоится.
    """
    if os.name != "nt":
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
        handle = kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)


_enable_windows_vt()


class _CRLFWriter:
    """Пишет CRLF вместо LF в терминал; в пайп/файл — как есть."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, s):
        if self._stream.isatty():
            return self._stream.write(s.replace("\n", "\r\n"))
        return self._stream.write(s)

    def flush(self):
        return self._stream.flush()

    def isatty(self):
        return self._stream.isatty()

    def fileno(self):
        return self._stream.fileno()

    def __getattr__(self, name):
        return getattr(self._stream, name)


if os.name == "nt":
    console = Console(record=True)
else:
    _stdout = _CRLFWriter(sys.stdout)
    sys.stdout = _stdout
    console = Console(record=True, file=_stdout)


def reset_record() -> None:
    """Очищает буфер записи консоли: экспорт ([S] / -o) содержит только
    результаты текущего прогона, без меню и служебных строк."""
    console._record_buffer.clear()
