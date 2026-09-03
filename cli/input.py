import asyncio
import sys
from cli.ui import _read_key_sync


async def _readline_cancelable() -> str:
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(None, sys.stdin.readline)
        result = await future
        return result.rstrip("\n")
    except asyncio.CancelledError:
        raise KeyboardInterrupt from None


def _flush_stdin() -> None:
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass


async def _read_key_cancelable() -> str:
    """Одна клавиша; если stdin не терминал — строка ввода (fallback)."""
    loop = asyncio.get_running_loop()
    if sys.stdin.isatty():
        return (await loop.run_in_executor(None, _read_key_sync)).lower()
    return (await _readline_cancelable()).strip().lower()


def _selection_flags(selection: str) -> tuple:
    """Раскладывает строку выбора ('0123'...) на флаги запуска тестов."""
    run_net_info  = "0" in selection   # Тест 0: информация о сети и системе
    run_dns_avail = "1" in selection   # Тест 1: доступность DNS-серверов
    run_domains   = "2" in selection   # Тест 2: доступность доменов (TLS/HTTP)
    run_tcp       = "3" in selection   # Тест 3: TCP 16-20KB блокировка
    run_wl_sni    = "4" in selection   # Тест 4: белые SNI для ASN
    run_telegram  = "5" in selection   # Тест 5: Telegram
    run_legend    = "6" in selection   # Тест 6: Легенда
    only_legend   = run_legend and not any([
        run_net_info, run_dns_avail, run_domains, run_tcp, run_wl_sni, run_telegram
    ])
    return (run_net_info, run_dns_avail, run_domains, run_tcp,
            run_wl_sni, run_telegram, run_legend, only_legend)
