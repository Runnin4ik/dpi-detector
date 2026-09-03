"""Глобальная rich-консоль приложения.

На POSIX (WSL, Linux) stdout оборачивается в CRLF-врайтер: если терминал
оказывается LF-only (OPOST отключён или обёртка не переводит LF в CRLF),
все строки "лесенкой" уходят вправо. При перенаправлении в файл/пайп
(isatty() = False) вывод остаётся LF.
"""


import os
import sys

from rich.console import Console


def is_wine() -> bool:
    """Проверяет, запущен ли процесс под Wine (PortProton, Wine на Linux/macOS)."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return hasattr(ctypes.windll.ntdll, "wine_get_version")
    except Exception:
        return False


def _enable_windows_vt() -> bool:
    """Включает обработку ANSI/VT в консоли Windows (ENABLE_VIRTUAL_TERMINAL_PROCESSING).

    Под Wine не включаем, так как Wine conhost сообщает об успехе SetConsoleMode,
    но не декодирует VT escape-последовательности, что ломает вывод Rich.
    Возвращает True, если VT успешно включён на реальной Windows.
    """
    if os.name != "nt" or is_wine():
        return False
    import ctypes

    try:
        kernel32 = ctypes.windll.kernel32
        success = True
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                    success = False
            else:
                success = False
        return success
    except Exception:
        return False


_vt_enabled = _enable_windows_vt()


def supports_vt() -> bool:
    """Поддерживает ли текущая консоль ANSI/VT escape-последовательности курсора."""
    if is_wine():
        return False
    if os.name == "nt":
        return bool(_vt_enabled)
    return sys.stdout.isatty()


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


def install_crlf_stdout() -> None:
    """Устанавливает CRLF-обёртку для sys.stdout при запуске CLI (не при импорте модуля)."""
    if os.name != "nt" and not isinstance(sys.stdout, _CRLFWriter):
        sys.stdout = _CRLFWriter(sys.stdout)


if os.name == "nt":
    console = Console(record=True, legacy_windows=True) if is_wine() else Console(record=True)
else:
    console = Console(record=True, file=_CRLFWriter(sys.stdout))


def reset_record() -> None:
    """Очищает буфер записи консоли: экспорт ([S] / -o) содержит только
    результаты текущего прогона, без меню и служебных строк."""
    console._record_buffer.clear()
