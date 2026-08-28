"""Глобальная rich-консоль приложения.

На POSIX (WSL, Linux) stdout оборачивается в CRLF-врайтер: если терминал
оказывается LF-only (OPOST отключён или обёртка не переводит LF в CRLF),
все строки "лесенкой" уходят вправо. При перенаправлении в файл/пайп
(isatty() = False) вывод остаётся LF.
"""

import os
import sys

from rich.console import Console


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
