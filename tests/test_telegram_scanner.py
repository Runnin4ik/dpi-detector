import unittest
import asyncio
import inspect
from core.telegram_scanner import (
    _fmt_speed, _fmt_size, _run_upload, _run_download,
    _check_dc, run_telegram_test
)


class TestTelegramScanner(unittest.TestCase):
    def test_format_helpers(self):
        self.assertEqual(_fmt_speed(0).strip(), "0 Б/с")
        self.assertEqual(_fmt_speed(500 * 1024).strip(), "500.0 КБ/с")
        self.assertEqual(_fmt_speed(10 * 1024 * 1024).strip(), "10.00 МБ/с")

        self.assertEqual(_fmt_size(0), "0 Б")
        self.assertEqual(_fmt_size(1024), "1.0 КБ")
        self.assertEqual(_fmt_size(5 * 1024 * 1024), "5.00 МБ")
    def test_functions_exist_and_are_coroutines(self):
        self.assertTrue(inspect.iscoroutinefunction(_run_upload))
        self.assertTrue(inspect.iscoroutinefunction(_run_download))
        self.assertTrue(inspect.iscoroutinefunction(_check_dc))
        self.assertTrue(inspect.iscoroutinefunction(run_telegram_test))


if __name__ == "__main__":
    unittest.main()
