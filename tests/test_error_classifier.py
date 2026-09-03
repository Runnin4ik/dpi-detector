import ssl
import errno
import unittest
import httpx
from utils.error_classifier import (
    ProbeStatus,
    classify_ssl_error,
    classify_connect_error,
    classify_read_error,
)


class TestErrorClassifier(unittest.TestCase):
    def test_classify_ssl_error(self):
        # 1. SSL alert unrecognized name
        err_alert = ssl.SSLError("SSLV3_ALERT_UNRECOGNIZED_NAME")
        label, detail, br = classify_ssl_error(err_alert, 0, stage="tls_handshake")
        self.assertIn("TLS ALERT", label)
        self.assertIn("SNI Block", detail)

        # 2. TLS spoof (wrong version)
        err_ver = ssl.SSLError("WRONG_VERSION_NUMBER")
        label, detail, br = classify_ssl_error(err_ver, 0, stage="tls_handshake")
        self.assertIn("TLS SPOOF", label)

        # 3. TLS RST (unexpected EOF on ClientHello)
        err_eof = ssl.SSLError("UNEXPECTED_EOF_WHILE_READING")
        label, detail, br = classify_ssl_error(err_eof, 0, stage="tls_handshake")
        self.assertIn("TLS RST", label)

        # 4. TLS MITM (self-signed cert)
        err_cert = ssl.SSLError("certificate verify failed: self-signed cert")
        label, detail, br = classify_ssl_error(err_cert, 0, stage="tls_handshake")
        self.assertIn("TLS MITM", label)

        # 5. NO CA BUNDLE (unable to get local issuer certificate / verify_code 20)
        err_no_ca = ssl.SSLCertVerificationError(
            "certificate verify failed: unable to get local issuer certificate (_ssl.c:1000)"
        )
        err_no_ca.verify_code = 20
        label_no_ca, detail_no_ca, br = classify_ssl_error(err_no_ca, 0, stage="tls_handshake")
        self.assertIn("NO CA BUNDLE", label_no_ca)
        self.assertIn("Отсутствуют корневые сертификаты", detail_no_ca)

        # 6. Hostname mismatch (verify_code 62)
        err_mismatch = ssl.SSLCertVerificationError("hostname mismatch: IP address mismatch")
        err_mismatch.verify_code = 62
        label_mismatch, detail_mismatch, br = classify_ssl_error(err_mismatch, 0, stage="tls_handshake")
        self.assertIn("TLS MITM", label_mismatch)
        self.assertIn("Hostname mismatch", detail_mismatch)

        # 7. ProbeStatus check
        self.assertEqual(ProbeStatus.NO_CA.value, "NO CA BUNDLE")
        self.assertFalse(ProbeStatus.is_blocked(label_no_ca))
        self.assertTrue(ProbeStatus.is_blocked(label_mismatch))

    def test_classify_connect_error(self):
        # TCP connection timeout
        err = httpx.ConnectTimeout("Connection timed out")
        label, detail, br = classify_connect_error(err, 0, stage="tcp_connect")
        self.assertTrue("TIMEOUT" in label or "DROP" in label or "SYN" in label)

        # Connection refused
        err_refused = ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
        label, detail, br = classify_connect_error(err_refused, 0, stage="tcp_connect")
        self.assertTrue("REFUSED" in label or "RST" in label or "ERR" in label)
        # SSL wrapped in ConnectError forwards stage
        nested = ssl.SSLError("UNEXPECTED_EOF_WHILE_READING")
        err_wrapped = httpx.ConnectError("SSL error")
        err_wrapped.__cause__ = nested
        label, detail, br = classify_connect_error(err_wrapped, 0, stage="tls_handshake")
        self.assertIn("TLS RST", label)
        err_reset = ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")
        label, detail, br = classify_read_error(err_reset, 0, stage="reading_data")
        self.assertTrue("RST" in label or "RESET" in label or "ABORT" in label)


if __name__ == "__main__":
    unittest.main()
