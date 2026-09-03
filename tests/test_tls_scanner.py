import math
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock
import httpx

from utils import config
from core.tls_scanner import _check_tls_single


class TestTlsScanner(unittest.IsolatedAsyncioTestCase):
    def test_tcp_block_threshold_logic(self):
        bytes_read_16k = 16 * 1024
        kb_read = math.ceil(bytes_read_16k / 1024)
        self.assertTrue(config.TCP_BLOCK_MIN_KB <= kb_read <= config.TCP_BLOCK_MAX_KB)

        bytes_read_20k = 20 * 1024
        kb_read_20 = math.ceil(bytes_read_20k / 1024)
        self.assertTrue(config.TCP_BLOCK_MIN_KB <= kb_read_20 <= config.TCP_BLOCK_MAX_KB)

        # Zero bytes should never trigger TCP16-20
        bytes_read_zero = 0
        kb_read_zero = math.ceil(bytes_read_zero / 1024)
        self.assertFalse(config.TCP_BLOCK_MIN_KB <= kb_read_zero <= config.TCP_BLOCK_MAX_KB)

    async def test_check_tls_single_read_timeout_tcp16_20(self):
        """Проверяет реальный сценарий: стриминг 18КБ и последующий ReadTimeout -> классификация TCP16-20."""
        sem = asyncio.Semaphore(1)

        async def fake_aiter_bytes():
            yield b"X" * 18 * 1024
            raise httpx.ReadTimeout("Read timed out after 18KB")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.aclose = AsyncMock()
        mock_resp.aiter_bytes = fake_aiter_bytes

        mock_client = MagicMock()
        mock_client.build_request = MagicMock(return_value=MagicMock())
        mock_client.send = AsyncMock(return_value=mock_resp)

        status, detail, br, elapsed = await _check_tls_single(
            "blocked.example.com", mock_client, sem, resolved_ip="1.2.3.4"
        )
        self.assertIn("TCP16-20", status)
        self.assertEqual(br, 18 * 1024)
        self.assertIn("18.0KB", detail)

    async def test_check_tls_single_ok_body_reading(self):
        """Проверяет успешное чтение тела ответа до 8КБ."""
        sem = asyncio.Semaphore(1)

        async def fake_aiter_bytes():
            yield b"OK" * 4096

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.aclose = AsyncMock()
        mock_resp.aiter_bytes = fake_aiter_bytes

        mock_client = MagicMock()
        mock_client.build_request = MagicMock(return_value=MagicMock())
        mock_client.send = AsyncMock(return_value=mock_resp)

        status, detail, br, elapsed = await _check_tls_single(
            "ok.example.com", mock_client, sem, resolved_ip="1.2.3.4"
        )
        self.assertIn("OK", status)
        self.assertEqual(br, 8192)

    async def test_check_tls_single_relative_redirect(self):
        """Относительный редирект на том же домене должен считаться легитимным REDIR."""
        sem = asyncio.Semaphore(1)
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"location": "/dashboard"}
        mock_resp.aclose = AsyncMock()

        mock_client = MagicMock()
        mock_client.build_request = MagicMock(return_value=MagicMock())
        mock_client.send = AsyncMock(return_value=mock_resp)

        status, detail, br, elapsed = await _check_tls_single(
            "example.com", mock_client, sem, resolved_ip="1.2.3.4"
        )
        self.assertTrue(status in ("[green]OK[/green]", "[green]REDIR[/green]"))
        self.assertNotIn("[bold red]", status)

    async def test_check_tls_single_suspicious_redirect(self):
        """Редирект на чужой домен должен помечаться как подозрительный."""
        sem = asyncio.Semaphore(1)
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {"location": "https://warning.isp.net/block"}
        mock_resp.aclose = AsyncMock()

        mock_client = MagicMock()
        mock_client.build_request = MagicMock(return_value=MagicMock())
        mock_client.send = AsyncMock(return_value=mock_resp)

        status, detail, br, elapsed = await _check_tls_single(
            "example.com", mock_client, sem, resolved_ip="1.2.3.4"
        )
        self.assertIn("[bold red]REDIR[/bold red]", status)
        self.assertIn("warning.isp.net", detail)

if __name__ == "__main__":
    unittest.main()
