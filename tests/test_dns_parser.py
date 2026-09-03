import struct
import socket
import unittest
from core.dns_scanner import _build_dns_query, _parse_dns_response, _parse_txt_response, _skip_dns_name


class TestDnsParser(unittest.TestCase):
    def test_skip_dns_name(self):
        # Root label
        self.assertEqual(_skip_dns_name(b"\x00", 0), 1)

        # Pure pointer: \xc0\x0c
        self.assertEqual(_skip_dns_name(b"\x00" * 12 + b"\xc0\x0c", 12), 14)

        # Non-compressed: 7example3com0
        data_nc = b"\x07example\x03com\x00\x00\x01\x00\x01"
        self.assertEqual(_skip_dns_name(data_nc, 0), 13)

        # Composite: label + pointer: \x03www\xc0\x0c
        data_lp = b"\x03www\xc0\x0c"
        self.assertEqual(_skip_dns_name(data_lp, 0), 6)

        # Multi-label + pointer: \x03foo\x03bar\xc0\x0c
        data_mlp = b"\x03foo\x03bar\xc0\x0c"
        self.assertEqual(_skip_dns_name(data_mlp, 0), 10)
        # Pointer loop protection (does not hang indefinitely)
        data_loop = b"\xc0\x00"
        self.assertEqual(_skip_dns_name(data_loop, 0), len(data_loop))

    def test_build_dns_query_idn(self):
        query = _build_dns_query("яндекс.рф")
        self.assertIn(b"xn--d1acpjx3f", query)
        self.assertIn(b"xn--p1ai", query)

        tx_id = b"\xaa\xbb"
        hdr = tx_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
        pkt = hdr + q + ans

        res = _parse_dns_response(pkt, tx_id)
        self.assertEqual(res, ["93.184.216.34"])

    def test_parse_dns_response_cname_chain(self):
        tx_id = b"\x12\x34"
        hdr = tx_id + b"\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00"
        # Question: www.example.com
        q = b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)

        # Answer 1: www.example.com CNAME example.com
        # Name is pointer to offset 12 (\xc0\x0c). Rdata is pointer to example.com at offset 16 (\xc0\x10)
        ans1 = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 300, 2) + b"\xc0\x10"

        # Answer 2: example.com A 93.184.216.34
        ans2 = b"\xc0\x10" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])

        pkt = hdr + q + ans1 + ans2
        res = _parse_dns_response(pkt, tx_id)
        self.assertEqual(res, ["93.184.216.34"])

    def test_parse_dns_response_composite_pointer_name(self):
        tx_id = b"\x56\x78"
        hdr = tx_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        # Question: example.com at offset 12
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)

        # Answer 1: sub.example.com -> \x03sub\xc0\x0c A 1.2.3.4
        ans = b"\x03sub\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])

        pkt = hdr + q + ans
        res = _parse_dns_response(pkt, tx_id)
        self.assertEqual(res, ["1.2.3.4"])

    def test_parse_dns_response_nxdomain(self):
        tx_id = b"\xab\xcd"
        # flags with rcode=3 (0x8183)
        hdr = tx_id + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        pkt = hdr + q

        res = _parse_dns_response(pkt, tx_id)
        self.assertEqual(res, "NXDOMAIN")

    def test_parse_dns_response_errors(self):
        tx_id = b"\xaa\xbb"
        # Short packet
        self.assertEqual(_parse_dns_response(b"\x00" * 8, tx_id), "PARSE_ERR")

        # Mismatched tx_id
        self.assertEqual(_parse_dns_response(b"\x11\x22" + b"\x00" * 20, tx_id), "PARSE_ERR")

    def test_parse_txt_response(self):
        tx_id = b"\x99\x99"
        hdr = tx_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)

        txt_content = b"v=spf1 -all"
        rdata = bytes([len(txt_content)]) + txt_content
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata

        pkt = hdr + q + ans
        res = _parse_txt_response(pkt)
        self.assertEqual(res, "v=spf1 -all")

    def test_parse_dns_response_aaaa(self):
        tx_id = b"\x12\x34"
        hdr = tx_id + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 28, 1)
        v6_bytes = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 300, 16) + v6_bytes
        pkt = hdr + q + ans
        res = _parse_dns_response(pkt, tx_id)
        self.assertEqual(res, ["2001:db8::1"])

if __name__ == "__main__":
    unittest.main()
