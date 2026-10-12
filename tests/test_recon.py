import datetime
import socket
import ssl
import struct
import unittest
from unittest.mock import patch

from vaptkit.recon import (
    _accepts_protocol,
    _days_to_expiry,
    dmarc_policy,
    dns_hygiene,
    fingerprint,
    parse_robots,
    parse_sitemap,
    parse_txt_response,
    scan_ports,
    subdomains,
    tls_hygiene,
)


def build_txt_response(txt_values: list[str]) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, len(txt_values), 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
    answers = b""
    for value in txt_values:
        rdata = bytes([len(value)]) + value.encode()
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
    return header + question + answers


class ParseTxtResponseTests(unittest.TestCase):
    def test_single_record_decoded(self):
        self.assertEqual(parse_txt_response(build_txt_response(["v=spf1 include:_spf.example.com ~all"])),
                         ["v=spf1 include:_spf.example.com ~all"])

    def test_multiple_records(self):
        self.assertEqual(parse_txt_response(build_txt_response(["v=DMARC1; p=reject", "google-site-verification=x"])),
                         ["v=DMARC1; p=reject", "google-site-verification=x"])

    def test_no_answers(self):
        self.assertEqual(parse_txt_response(build_txt_response([])), [])


class DmarcPolicyTests(unittest.TestCase):
    def test_extracts_policy(self):
        self.assertEqual(dmarc_policy(["v=DMARC1; p=reject; rua=mailto:x@example.com"]), "reject")

    def test_none_when_absent(self):
        self.assertIsNone(dmarc_policy([]))


class DnsHygieneTests(unittest.TestCase):
    def test_both_absent_when_dns_unreachable(self):
        with patch("vaptkit.recon.dns_txt", return_value=[]):
            self.assertEqual(dns_hygiene("example.invalid"),
                             {"spf_present": False, "dmarc_present": False, "dmarc_policy": None})

    def test_detects_spf_and_dmarc(self):
        def fake(name, **kwargs):
            if name == "example.invalid":
                return ["v=spf1 -all"]
            return ["v=DMARC1; p=quarantine"]
        with patch("vaptkit.recon.dns_txt", side_effect=fake):
            self.assertEqual(dns_hygiene("example.invalid"),
                             {"spf_present": True, "dmarc_present": True, "dmarc_policy": "quarantine"})


class SubdomainsTests(unittest.TestCase):
    def test_network_failure_returns_empty_not_raise(self):
        with patch("vaptkit.recon.http.client.HTTPSConnection", side_effect=OSError("no route")):
            self.assertEqual(subdomains("example.invalid"), [])

    def test_dedupes_and_excludes_apex_and_other_domains(self):
        class Response:
            status = 200
            def read(self, limit):
                return (b'[{"name_value":"*.api.example.invalid\\napi.example.invalid"},'
                       b'{"name_value":"example.invalid"},{"name_value":"api.example.invalid"},'
                       b'{"name_value":"sub.other.invalid"}]')

        class Connection:
            def __init__(self, *a, **k): pass
            def request(self, *a, **k): pass
            def getresponse(self): return Response()
            def close(self): pass

        with patch("vaptkit.recon.http.client.HTTPSConnection", return_value=Connection()):
            self.assertEqual(subdomains("example.invalid"), ["api.example.invalid"])


class ScanPortsTests(unittest.TestCase):
    def test_only_connectable_ports_are_reported(self):
        class FakeSocket:
            def __init__(self, *a, **k): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, value): pass
            def connect_ex(self, address):
                return 0 if address[1] in (80, 443) else 111

        with patch("vaptkit.recon.socket.socket", return_value=FakeSocket()):
            self.assertEqual(scan_ports("203.0.113.5", ports=(22, 80, 443, 3306)), [80, 443])

    def test_no_open_ports_returns_empty_list(self):
        class FakeSocket:
            def __init__(self, *a, **k): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def settimeout(self, value): pass
            def connect_ex(self, address): return 111

        with patch("vaptkit.recon.socket.socket", return_value=FakeSocket()):
            self.assertEqual(scan_ports("203.0.113.5", ports=(22, 3306)), [])


class AcceptsProtocolTests(unittest.TestCase):
    def test_true_on_successful_handshake(self):
        class FakeTlsSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class FakeContext:
            def __init__(self, *a, **k): pass
            check_hostname = True
            verify_mode = None
            minimum_version = None
            maximum_version = None
            def wrap_socket(self, sock, server_hostname=None): return FakeTlsSocket()

        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch("vaptkit.recon.socket.create_connection", return_value=FakeSocket()), \
             patch("vaptkit.recon.ssl.SSLContext", return_value=FakeContext()):
            self.assertTrue(_accepts_protocol("example.invalid", 443, ssl.TLSVersion.TLSv1, 1.0))

    def test_false_when_handshake_rejected(self):
        with patch("vaptkit.recon.socket.create_connection", side_effect=ssl.SSLError("no protocols available")):
            self.assertFalse(_accepts_protocol("example.invalid", 443, ssl.TLSVersion.TLSv1, 1.0))

    def test_false_when_connection_refused(self):
        with patch("vaptkit.recon.socket.create_connection", side_effect=OSError("refused")):
            self.assertFalse(_accepts_protocol("example.invalid", 443, ssl.TLSVersion.TLSv1, 1.0))


class DaysToExpiryTests(unittest.TestCase):
    def test_none_when_no_not_after(self):
        self.assertIsNone(_days_to_expiry({}))

    def test_computes_days_remaining(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=15)
        cert = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
        self.assertEqual(_days_to_expiry(cert), 14)

    def test_negative_when_already_expired(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=5)
        cert = {"notAfter": past.strftime("%b %d %H:%M:%S %Y GMT")}
        self.assertLess(_days_to_expiry(cert), 0)


class TlsHygieneTests(unittest.TestCase):
    def test_connection_failure_returns_all_none_not_raise(self):
        with patch("vaptkit.recon.socket.create_connection", side_effect=OSError("refused")), \
             patch("vaptkit.recon._accepts_protocol", return_value=False):
            self.assertEqual(tls_hygiene("example.invalid"),
                             {"legacy_protocols_supported": [], "negotiated_cipher": None,
                              "cert_days_to_expiry": None})

    def test_reports_legacy_protocol_cipher_and_expiry(self):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)

        class FakeTlsSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def cipher(self): return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
            def getpeercert(self): return {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}

        class FakeContext:
            def wrap_socket(self, sock, server_hostname=None): return FakeTlsSocket()

        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def fake_accepts(host, port, version, timeout):
            return version == ssl.TLSVersion.TLSv1

        with patch("vaptkit.recon.socket.create_connection", return_value=FakeSocket()), \
             patch("vaptkit.recon.ssl.create_default_context", return_value=FakeContext()), \
             patch("vaptkit.recon._accepts_protocol", side_effect=fake_accepts):
            result = tls_hygiene("example.invalid")
        self.assertEqual(result["legacy_protocols_supported"], ["TLSv1.0"])
        self.assertEqual(result["negotiated_cipher"], "TLS_AES_128_GCM_SHA256")
        self.assertEqual(result["cert_days_to_expiry"], 9)


class ParseRobotsTests(unittest.TestCase):
    def test_extracts_disallow_paths(self):
        body = b"User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nAllow: /\n"
        self.assertEqual(parse_robots(body), ["/admin", "/api/internal"])

    def test_ignores_blanket_disallow_and_wildcards(self):
        body = b"Disallow: /\nDisallow: /tmp/*\n"
        self.assertEqual(parse_robots(body), [])

    def test_empty_body_returns_empty_list(self):
        self.assertEqual(parse_robots(b""), [])

    def test_dedupes_repeated_paths(self):
        body = b"Disallow: /admin\nDisallow: /admin\n"
        self.assertEqual(parse_robots(body), ["/admin"])


class ParseSitemapTests(unittest.TestCase):
    def test_extracts_path_only_from_urls(self):
        body = b"<urlset><url><loc>https://example.invalid/a/b</loc></url>" \
               b"<url><loc>https://example.invalid/c</loc></url></urlset>"
        self.assertEqual(parse_sitemap(body), ["/a/b", "/c"])

    def test_dedupes_and_sorts(self):
        body = b"<loc>https://x.invalid/b</loc><loc>https://x.invalid/a</loc><loc>https://x.invalid/a</loc>"
        self.assertEqual(parse_sitemap(body), ["/a", "/b"])

    def test_empty_body_returns_empty_list(self):
        self.assertEqual(parse_sitemap(b""), [])


class FingerprintTests(unittest.TestCase):
    def test_detects_from_body_signature(self):
        self.assertIn("Next.js", fingerprint({}, b'<script id="__NEXT_DATA__">{}</script>'))

    def test_detects_from_header(self):
        self.assertEqual(fingerprint({"server": ["nginx/1.24.0"]}, b""), ["nginx"])

    def test_no_false_positive_on_unrelated_content(self):
        self.assertEqual(fingerprint({"server": ["cloudflare"]}, b"<html>hi</html>"), [])


if __name__ == "__main__":
    unittest.main()
