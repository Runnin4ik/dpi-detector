import unittest
import tempfile
from pathlib import Path
from utils import config


class TestConfigValidation(unittest.TestCase):
    def test_default_values_present(self):
        self.assertGreater(config.MAX_CONCURRENT, 0)
        self.assertIn(config.IP_VERSION, ("ipv4", "ipv6"))
        self.assertGreater(config.CONNECT_TIMEOUT, 0.0)
        self.assertGreater(config.DNS_PROBE_CONCURRENCY, 0)
        self.assertEqual(config.DNS_STUB_THRESHOLD, 2)

    def test_protected_keys_cannot_be_overwritten(self):
        yaml_content = """
CONFIG_LOAD_ERROR: "HACKED"
CONFIG_WARNINGS: ["HACKED"]
load_config: "HACKED"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            ok = config.load_config(temp_path)
            self.assertTrue(ok)
            self.assertIsNone(config.CONFIG_LOAD_ERROR)
            self.assertTrue(callable(config.load_config))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_type_and_range_validation_retains_default(self):
        default_concurrent = config.MAX_CONCURRENT
        default_ip_version = config.IP_VERSION

        yaml_content = """
MAX_CONCURRENT: "one hundred"
IP_VERSION: "ipv5"
CONNECT_TIMEOUT: -5.0
UNKNOWN_SECRET_KEY: 12345
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            ok = config.load_config(temp_path)
            self.assertTrue(ok)
            # Defaults should be preserved
            self.assertEqual(config.MAX_CONCURRENT, default_concurrent)
            self.assertEqual(config.IP_VERSION, default_ip_version)
            # Warnings should be collected
            warning_text = " ".join(config.CONFIG_WARNINGS)
            self.assertIn("MAX_CONCURRENT", warning_text)
            self.assertIn("IP_VERSION", warning_text)
            self.assertIn("CONNECT_TIMEOUT", warning_text)
            self.assertIn("UNKNOWN_SECRET_KEY", warning_text)
        finally:
            temp_path.unlink(missing_ok=True)
            # Restore standard config
            config.load_config()

    def test_valid_custom_config_loads_successfully(self):
        yaml_content = """
MAX_CONCURRENT: 25
IP_VERSION: "ipv6"
CONNECT_TIMEOUT: 15.0
DNS_STUB_THRESHOLD: 3
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(yaml_content)
            temp_path = Path(f.name)

        try:
            ok = config.load_config(temp_path)
            self.assertTrue(ok)
            self.assertEqual(config.MAX_CONCURRENT, 25)
            self.assertEqual(config.IP_VERSION, "ipv6")
            self.assertEqual(config.CONNECT_TIMEOUT, 15.0)
            self.assertEqual(config.DNS_STUB_THRESHOLD, 3)
            self.assertEqual(len(config.CONFIG_WARNINGS), 0)
        finally:
            temp_path.unlink(missing_ok=True)
            # Restore standard config
            config.load_config()


if __name__ == "__main__":
    unittest.main()
