import unittest
from utils.version import is_newer
from utils.network import mask_proxy_url
from cli.netinfo import _flag_emoji
from cli.input import _selection_flags
from cli.ui import clean_hostname, build_domain_row
from utils.files import load_domains, load_tcp_targets

class TestHelpers(unittest.TestCase):
    def test_is_newer(self):
        self.assertTrue(is_newer("4.2.2", "4.2.1"))
        self.assertTrue(is_newer("v4.3.0", "4.2.1"))
        self.assertTrue(is_newer("5.0.0", "4.9.9"))
        self.assertTrue(is_newer("4.2.2-rc1", "4.2.1"))
        self.assertTrue(is_newer("4.3", "4.2.1"))
        self.assertFalse(is_newer("4.2.1", "4.2.1"))
        self.assertFalse(is_newer("4.2.0", "4.2.1"))
        self.assertFalse(is_newer("invalid", "4.2.1"))

    def test_mask_proxy_url(self):
        self.assertEqual(mask_proxy_url("socks5://user:secret@127.0.0.1:1080"), "socks5://user:***@127.0.0.1:1080")
        self.assertEqual(mask_proxy_url("http://admin:pass123@proxy.com:8080/path"), "http://admin:***@proxy.com:8080/path")
        self.assertEqual(mask_proxy_url("socks5://127.0.0.1:1080"), "socks5://127.0.0.1:1080")
        self.assertEqual(mask_proxy_url("http://localhost:8080"), "http://localhost:8080")
        self.assertEqual(mask_proxy_url(""), "")
        self.assertEqual(mask_proxy_url(None), "")

    def test_flag_emoji(self):
        self.assertEqual(_flag_emoji("RU"), "🇷🇺")
        self.assertEqual(_flag_emoji("US"), "🇺🇸")
        self.assertEqual(_flag_emoji("de"), "🇩🇪")
        self.assertEqual(_flag_emoji("invalid"), "")
        self.assertEqual(_flag_emoji("12"), "")
        self.assertEqual(_flag_emoji(""), "")

    def test_selection_flags(self):
        (run_net, run_dns, run_dom, run_tcp, run_wl, run_tg, run_leg, only_leg) = _selection_flags("123")
        self.assertFalse(run_net)
        self.assertTrue(run_dns)
        self.assertTrue(run_dom)
        self.assertTrue(run_tcp)
        self.assertFalse(run_wl)
        self.assertFalse(run_tg)
        self.assertFalse(run_leg)
        self.assertFalse(only_leg)

        (run_net, run_dns, run_dom, run_tcp, run_wl, run_tg, run_leg, only_leg) = _selection_flags("6")
        self.assertTrue(run_leg)
        self.assertTrue(only_leg)

        (run_net, run_dns, run_dom, run_tcp, run_wl, run_tg, run_leg, only_leg) = _selection_flags("06")
        self.assertTrue(run_net)
        self.assertTrue(run_leg)
        self.assertFalse(only_leg)
    def test_clean_hostname(self):
        self.assertEqual(clean_hostname("https://example.com/test"), "example.com")
        self.assertEqual(clean_hostname("example.com:8443"), "example.com")
        self.assertEqual(clean_hostname("http://[2001:db8::1]:8080"), "2001:db8::1")
        self.assertEqual(clean_hostname("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(clean_hostname("2001:db8::1"), "2001:db8::1")
        self.assertEqual(clean_hostname("1.2.3.4:80"), "1.2.3.4")
        self.assertEqual(clean_hostname("1.2.3.4"), "1.2.3.4")

    def test_build_domain_row(self):
        entry = {
            "domain": "example.com",
            "resolved_ipv4": "93.184.216.34",
            "dns_fake": False,
            "http_res": ("[green]OK[/green]", "HTTP 200"),
            "t12_res": ("[green]OK[/green]", "HTTP 200", 0.12),
            "t13v4_res": ("[green]OK[/green]", "HTTP 200", 0.10),
        }
        row = build_domain_row(entry)
        self.assertEqual(row[0], "example.com")
        self.assertEqual(row[1], "[green]OK[/green]")
        self.assertEqual(row[2], "[green]OK[/green]")
        self.assertEqual(row[3], "[green]OK[/green]")
        self.assertEqual(row[5], "93.184.216.34")

    def test_file_loaders_raise_on_error(self):
        with self.assertRaises(FileNotFoundError):
            load_domains("non_existent_file_12345.txt", raise_on_error=True)
        with self.assertRaises(FileNotFoundError):
            load_tcp_targets("non_existent_file_12345.json", raise_on_error=True)

    def test_get_fake_ip_type_ipv6(self):
        from utils.network import get_fake_ip_type
        self.assertEqual(get_fake_ip_type("::1"), "local")
        self.assertEqual(get_fake_ip_type("fe80::1"), "local")
        self.assertEqual(get_fake_ip_type("fc00::1"), "local")
        self.assertIsNone(get_fake_ip_type("2606:4700:4700::1111"))

    def test_tcp16_json_integrity(self):
        targets = load_tcp_targets("tcp16.json", raise_on_error=True)
        self.assertGreater(len(targets), 0)
        ids = [t["id"] for t in targets]
        self.assertEqual(len(ids), len(set(ids)), "tcp16.json содержит дубликаты id!")
        for item_id in ids:
            self.assertTrue(item_id.isascii(), f"id {item_id} содержит не-ASCII символы!")

    def test_parse_arguments_tests_validation(self):
        import sys
        from dpi_detector import parse_arguments
        orig_argv = sys.argv
        try:
            sys.argv = ["dpi_detector.py", "--tests", "123"]
            args = parse_arguments()
            self.assertEqual(args.tests, "123")

            sys.argv = ["dpi_detector.py", "--tests", "1x"]
            with self.assertRaises(SystemExit):
                parse_arguments()

            sys.argv = ["dpi_detector.py", "--concurrency", "0"]
            with self.assertRaises(SystemExit):
                parse_arguments()
        finally:
            sys.argv = orig_argv
    def test_parse_socks_proxy(self):
        from core.dns_scanner import _parse_socks_proxy
        # IPv4
        self.assertEqual(_parse_socks_proxy("socks5://127.0.0.1:1080"), ("127.0.0.1", 1080, None, None))
        # Auth
        self.assertEqual(_parse_socks_proxy("socks5://user:pass@192.168.1.1:9050"), ("192.168.1.1", 9050, "user", "pass"))
        # Percent-encoded
        self.assertEqual(_parse_socks_proxy("socks5://u%40ser:p%40ss@proxy.com:1080"), ("proxy.com", 1080, "u@ser", "p@ss"))
        # IPv6
        self.assertEqual(_parse_socks_proxy("socks5://[::1]:1080"), ("::1", 1080, None, None))
        self.assertEqual(_parse_socks_proxy("socks5h://[2001:db8::1]:8080"), ("2001:db8::1", 8080, None, None))
        # Invalid
        self.assertIsNone(_parse_socks_proxy("http://127.0.0.1:8080"))
        self.assertIsNone(_parse_socks_proxy("socks5://127.0.0.1:99999"))
        self.assertIsNone(_parse_socks_proxy(""))
        self.assertIsNone(_parse_socks_proxy(None))

    def test_create_insecure_dpi_ssl_context(self):
        import ssl
        from utils.network import create_insecure_dpi_ssl_context
        ctx = create_insecure_dpi_ssl_context()
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

        ctx12 = create_insecure_dpi_ssl_context(tls_version="TLSv1.2")
        self.assertEqual(ctx12.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(ctx12.maximum_version, ssl.TLSVersion.TLSv1_2)
    def test_header_banner_and_version(self):
        from cli.header import render_banner, version_badge
        panel, lines = render_banner("✓ Актуальная версия")
        self.assertIsNotNone(panel)
        self.assertEqual(lines, 4)

        badge_none = version_badge(None)
        self.assertIn("Не удалось", badge_none)

        badge_new = version_badge({"version": "99.0.0"})
        self.assertIn("99.0.0", badge_new)

        badge_cur = version_badge({"version": "4.2.1"})
        self.assertIn("Актуальная", badge_cur)
if __name__ == "__main__":
    unittest.main()
