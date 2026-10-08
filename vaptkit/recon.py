"""Passive, non-target reconnaissance: subdomains, DMARC/SPF hygiene, tech fingerprinting and ports.

Subdomains and DNS hygiene only talk to public third-party services (certificate transparency
logs and public DNS resolvers), not the target, so unlike exposure.py they do not need an approval
or scope check to run. Tech fingerprinting reuses the homepage response the staging check already
fetched instead of making its own request. Port scanning does touch the target (a plain TCP
connect, no payload, to a short list of common ports - the same thing `nmap -p- -A -sV -Pn` looks
for) so it is gated by the caller behind the same approval and public-address check as everything
else that talks to the target.
"""
import http.client
import json
import re
import socket
import ssl
import struct

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


def dns_hygiene(domain: str) -> dict:
    """SPF and DMARC presence for `domain` - zero network calls to the target, DNS only."""
    spf = [record for record in dns_txt(domain) if record.lower().startswith("v=spf1")]
    dmarc = [record for record in dns_txt(f"_dmarc.{domain}") if record.lower().startswith("v=dmarc1")]
    return {"spf_present": bool(spf), "dmarc_present": bool(dmarc), "dmarc_policy": dmarc_policy(dmarc)}


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
