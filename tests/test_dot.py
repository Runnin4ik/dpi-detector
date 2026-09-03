import ssl
import unittest
from core.dns.dot import _split_dot_endpoint, create_dot_ssl_context


class TestDot(unittest.TestCase):
    def test_split_dot_endpoint(self):
        # Default port 853
        self.assertEqual(_split_dot_endpoint("dns.google"), ("dns.google", 853))
        self.assertEqual(_split_dot_endpoint("8.8.8.8"), ("8.8.8.8", 853))

        # Explicit custom port
        self.assertEqual(_split_dot_endpoint("dns.google:8853"), ("dns.google", 8853))
        self.assertEqual(_split_dot_endpoint("1.1.1.1:853"), ("1.1.1.1", 853))

        # IPv6
        self.assertEqual(_split_dot_endpoint("[2001:4860:4860::8888]"), ("2001:4860:4860::8888", 853))
        self.assertEqual(_split_dot_endpoint("[2001:4860:4860::8888]:8853"), ("2001:4860:4860::8888", 8853))
        self.assertEqual(_split_dot_endpoint("2001:4860:4860::8888"), ("2001:4860:4860::8888", 853))

    def test_create_dot_ssl_context(self):
        ctx = create_dot_ssl_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
