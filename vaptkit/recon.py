"""Passive, non-target reconnaissance: subdomains, DMARC/SPF hygiene, tech fingerprinting, ports and TLS.

Subdomains and DNS hygiene only talk to public third-party services (certificate transparency
logs and public DNS resolvers), not the target, so unlike exposure.py they do not need an approval
or scope check to run. Tech fingerprinting reuses the homepage response the staging check already
fetched instead of making its own request. Port scanning and TLS hygiene do touch the target (a
plain TCP connect, no payload, and a normal plus two deliberately-legacy TLS handshakes - the same
things `nmap -p- -A -sV -Pn` and `--script ssl-enum-ciphers` look for) so both are gated by the
caller behind the same approval and public-address check as everything else that talks to the target.
"""
import datetime
import http.client
import json
import re
import socket
import ssl
import struct
from urllib.parse import urlsplit

DNS_SERVERS = ("8.8.8.8", "1.1.1.1")
CRT_SH_HOST = "crt.sh"
COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
)


def scan_ports(ip: str, ports: tuple[int, ...] = COMMON_PORTS, *, timeout: float = 1.0) -> list[int]:
    """Open TCP ports on `ip` from a short, common-service list - a plain connect, no payload sent."""
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports


LEGACY_TLS_VERSIONS = (
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
)


def tls_hygiene(host: str, port: int = 443, *, timeout: float = 5.0) -> dict:
    """TLS protocol and certificate hygiene - the stdlib equivalent of `nmap --script
    ssl-enum-ciphers`, without shelling out to nmap. Reports which legacy protocol versions
    (SSLv3/TLSv1.0/TLSv1.1) the server still accepts, the cipher negotiated on a normal
    connection, and days until the certificate expires. Any connection failure (including a
    plain HTTP target with nothing on 443) is reported as "nothing found", not an error, the
    same convention as dns_hygiene/subdomains.
    """
    legacy_supported = [name for name, tls_version in LEGACY_TLS_VERSIONS
                        if tls_version is not None and _accepts_protocol(host, port, tls_version, timeout)]
    negotiated_cipher, cert_days_to_expiry = None, None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher()
                negotiated_cipher = cipher[0] if cipher else None
                cert = tls_sock.getpeercert()
        cert_days_to_expiry = _days_to_expiry(cert) if cert else None
    except (OSError, ssl.SSLError):
        pass
    return {
        "legacy_protocols_supported": legacy_supported,
        "negotiated_cipher": negotiated_cipher,
        "cert_days_to_expiry": cert_days_to_expiry,
    }


def _accepts_protocol(host: str, port: int, tls_version, timeout: float) -> bool:
    """Whether the server completes a handshake pinned to exactly `tls_version`."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError):
        return False


def _days_to_expiry(cert: dict) -> int | None:
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    expires = expires.replace(tzinfo=datetime.timezone.utc)
    return (expires - datetime.datetime.now(datetime.timezone.utc)).days


def dns_txt(name: str, *, timeout: float = 5.0) -> list[str]:
    """TXT records for `name`, via a minimal hand-built DNS query (no extra dependency or binary)."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    question += struct.pack(">HH", 16, 1)  # TYPE=TXT, CLASS=IN
    packet = header + question
    for server in DNS_SERVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (server, 53))
                response, _ = sock.recvfrom(4096)
            return parse_txt_response(response)
        except OSError:
            continue
    return []


def parse_txt_response(response: bytes) -> list[str]:
    ancount = struct.unpack(">H", response[6:8])[0]
    offset = 12
    while response[offset] != 0:
        offset += response[offset] + 1
    offset += 5  # null byte + QTYPE + QCLASS
    records = []
    for _ in range(ancount):
        while response[offset] & 0xC0 != 0xC0 and response[offset] != 0:
            offset += response[offset] + 1
        offset += 2 if response[offset] & 0xC0 else 1
        rtype, _, _, rdlength = struct.unpack(">HHIH", response[offset:offset + 10])
        offset += 10
        data = response[offset:offset + rdlength]
        if rtype == 16:
            pieces, pos = [], 0
            while pos < len(data):
                length = data[pos]
                pieces.append(data[pos + 1:pos + 1 + length])
                pos += length + 1
            records.append(b"".join(pieces).decode("utf-8", "replace"))
        offset += rdlength
    return records


COMMON_DKIM_SELECTORS = (
    "default", "selector1", "selector2", "google", "k1", "k2", "dkim", "mail", "smtp", "s1", "s2",
)


def dkim_selectors_found(domain: str) -> list[str]:
    """Common DKIM selectors that publish a v=DKIM1 TXT record for `domain`. Not exhaustive: the
    actual selector is chosen by the mail provider and is not discoverable without seeing a real
    signed email's DKIM-Signature header, so an empty result does not mean DKIM is unconfigured -
    only that none of these common names are in use.
    """
    return [selector for selector in COMMON_DKIM_SELECTORS
           if any(record.lower().startswith("v=dkim1") for record in dns_txt(f"{selector}._domainkey.{domain}"))]


def dns_hygiene(domain: str) -> dict:
    """SPF, DMARC and best-effort DKIM presence for `domain` - zero network calls to the target, DNS only."""
    spf = [record for record in dns_txt(domain) if record.lower().startswith("v=spf1")]
    dmarc = [record for record in dns_txt(f"_dmarc.{domain}") if record.lower().startswith("v=dmarc1")]
    return {"spf_present": bool(spf), "dmarc_present": bool(dmarc), "dmarc_policy": dmarc_policy(dmarc),
           "dkim_selectors_found": dkim_selectors_found(domain)}


def dmarc_policy(dmarc_records: list[str]) -> str | None:
    for record in dmarc_records:
        match = re.search(r"(?i)\bp=(\w+)", record)
        if match:
            return match.group(1).lower()
    return None


def subdomains(domain: str, *, timeout: float = 10.0) -> list[str]:
    """Subdomains seen in certificate-transparency logs (crt.sh), passive and off-target."""
    try:
        connection = http.client.HTTPSConnection(CRT_SH_HOST, 443, timeout=timeout)
        try:
            connection.request("GET", f"/?q=%25.{domain}&output=json",
                               headers={"User-Agent": "Matt-VAPT-Kit (passive-recon)"})
            response = connection.getresponse()
            if response.status != 200:
                return []
            body = response.read(1_000_000)
        finally:
            connection.close()
        entries = json.loads(body)
    except (OSError, ssl.SSLError, json.JSONDecodeError, ValueError):
        return []
    names = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and name != domain and name.endswith("." + domain):
                names.add(name)
    return sorted(names)


TECH_SIGNATURES = (
    ("Next.js", re.compile(rb'"buildId"\s*:\s*"'), None),
    ("Next.js", re.compile(rb'__NEXT_DATA__'), None),
    ("React", re.compile(rb'data-reactroot|__REACT_DEVTOOLS'), None),
    ("WordPress", re.compile(rb'wp-content/|wp-includes/'), None),
    ("Express", None, re.compile(r"^Express$", re.IGNORECASE)),
    ("Next.js", None, re.compile(r"^Next\.js$", re.IGNORECASE)),
    ("PHP", None, re.compile(r"^PHP/([\d.]+)", re.IGNORECASE)),
    ("Apache", None, re.compile(r"^Apache(?:/([\d.]+))?", re.IGNORECASE)),
    ("nginx", None, re.compile(r"^nginx(?:/([\d.]+))?", re.IGNORECASE)),
)


ROBOTS_DISALLOW = re.compile(rb"(?im)^\s*disallow\s*:\s*(\S+)")
SITEMAP_LOC = re.compile(rb"<loc>\s*([^<\s]+)\s*</loc>")


def parse_robots(body: bytes) -> list[str]:
    """Disallowed paths listed in a robots.txt body - free recon from a file sites publish on purpose."""
    paths = set()
    for match in ROBOTS_DISALLOW.finditer(body):
        path = match.group(1).decode("ascii", "replace")
        if path and path != "/" and "*" not in path:
            paths.add(path[:256])
    return sorted(paths)[:100]


def parse_sitemap(body: bytes) -> list[str]:
    """Paths listed in a sitemap.xml's <loc> entries - scheme and host stripped, path only."""
    paths = set()
    for match in SITEMAP_LOC.finditer(body):
        url = match.group(1).decode("ascii", "replace")
        paths.add((urlsplit(url).path or "/")[:256])
    return sorted(paths)[:100]


HREF = re.compile(rb'<a[^>]+href=["\']([^"\'#]+)["\']', re.IGNORECASE)
SKIPPED_SCHEMES = ("mailto:", "tel:", "javascript:", "data:")


def extract_same_origin_links(host: str, body: bytes) -> list[str]:
    """Same-origin page paths linked from an HTML body via <a href> - the one piece of Burp's
    crawling/spidering role this kit didn't already cover (directory lists, DNS/subdomains,
    fingerprinting and ports already mirror the rest of the NCERT-style toolset). Only looks at
    the homepage already fetched for fingerprinting/source-map discovery; this is not a multi-page
    crawl - deliberately shallow, matching the kit's "no extra requests beyond what's already
    being fetched" bias for anything passive, and the caller still confirms reachability before
    trusting any of these as real.
    """
    paths = []
    for match in HREF.finditer(body):
        href = match.group(1).decode("utf-8", "replace").strip()
        if not href or href.startswith("//") or href.lower().startswith(SKIPPED_SCHEMES):
            continue
        if href.startswith(("http://", "https://")):
            parsed = urlsplit(href)
            if parsed.hostname != host:
                continue
            path = parsed.path or "/"
        elif href.startswith("/"):
            path = urlsplit(href).path or "/"
        else:
            continue
        if path not in ("/", "") and path not in paths:
            paths.append(path[:256])
    return paths[:25]


def fingerprint(headers: dict[str, list[str]], body: bytes) -> list[str]:
    """Technology names detected from response headers/body - the same signal Wappalyzer uses."""
    found = set()
    powered_by = (headers.get("x-powered-by") or [""])[0]
    server = (headers.get("server") or [""])[0]
    for name, body_pattern, header_pattern in TECH_SIGNATURES:
        if body_pattern and body_pattern.search(body):
            found.add(name)
        if header_pattern and (header_pattern.search(powered_by) or header_pattern.search(server)):
            found.add(name)
    return sorted(found)
