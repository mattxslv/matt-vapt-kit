"""Fixed-list public exposure checks with soft-404 baselining and signature confirmation.

Only derived facts are kept (status, content-type class, signature matched or not).
Response bodies are read into memory up to a small limit and never written anywhere.
"""
import re
import secrets

# (path, kind, signature regex applied to the first 2 KB, severity, title)
CHECKS = (
    ("/.env", "secret_file", rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file publicly downloadable"),
    ("/.env.local", "secret_file", rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file publicly downloadable"),
    ("/.env.production", "secret_file", rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file publicly downloadable"),
    ("/.git/HEAD", "vcs", rb"^ref: refs/|^[0-9a-f]{40}\s*$", "high", "Git repository metadata publicly downloadable"),
    ("/.git/config", "vcs", rb"\[core\]", "high", "Git repository metadata publicly downloadable"),
    ("/api/debug", "debug", None, "medium", "Debug endpoint publicly reachable"),
    ("/api/env", "debug", None, "medium", "Debug endpoint publicly reachable"),
    ("/api/config", "debug", None, "medium", "Debug endpoint publicly reachable"),
    ("/api/health", "health", None, "low", "Health endpoint discloses internal details"),
    ("/swagger.json", "api_docs", rb"\"(?:swagger|openapi)\"\s*:", "low", "API documentation publicly reachable"),
    ("/openapi.json", "api_docs", rb"\"(?:swagger|openapi)\"\s*:", "low", "API documentation publicly reachable"),
    ("/api-docs", "api_docs", rb"(?i)swagger|openapi", "low", "API documentation publicly reachable"),
    # The rest mirror what directory-busting tools (dirsearch, feroxbuster) probe by default.
    ("/.env.staging", "secret_file", rb"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", "high", "Environment file publicly downloadable"),
    ("/.aws/credentials", "secret_file", rb"(?i)aws_access_key_id|\[default\]", "high", "Cloud credentials file publicly downloadable"),
    ("/.npmrc", "secret_file", rb"_authToken\s*=|//registry\.", "high", "Package manager credentials file publicly downloadable"),
    ("/.vscode/sftp.json", "secret_file", rb"\"host\"\s*:", "high", "Deployment credentials file publicly downloadable"),
    ("/.svn/entries", "vcs", rb"^\d+\s*$|svn:", "high", "Version-control metadata publicly downloadable"),
    ("/.hg/hgrc", "vcs", rb"\[paths\]|\[ui\]", "high", "Version-control metadata publicly downloadable"),
    ("/backup.sql", "backup_file", rb"(?i)create table|insert into|-- (mysql|postgresql) dump", "high", "Database backup publicly downloadable"),
    ("/database.sql", "backup_file", rb"(?i)create table|insert into|-- (mysql|postgresql) dump", "high", "Database backup publicly downloadable"),
    ("/dump.sql", "backup_file", rb"(?i)create table|insert into|-- (mysql|postgresql) dump", "high", "Database backup publicly downloadable"),
    ("/backup.zip", "backup_file", rb"^PK\x03\x04", "high", "Site backup archive publicly downloadable"),
    ("/site-backup.zip", "backup_file", rb"^PK\x03\x04", "high", "Site backup archive publicly downloadable"),
    ("/www.zip", "backup_file", rb"^PK\x03\x04", "high", "Site backup archive publicly downloadable"),
    ("/.htpasswd", "secret_file", rb"^[\w.\-]+:\$", "high", "Password hash file publicly downloadable"),
    ("/web.config", "config_file", rb"(?i)<configuration", "medium", "Server configuration file publicly downloadable"),
    ("/docker-compose.yml", "config_file", rb"(?i)^services:", "medium", "Deployment configuration file publicly downloadable"),
    ("/phpinfo.php", "debug", rb"(?i)<title>phpinfo\(\)</title>", "medium", "Debug endpoint publicly reachable"),
    ("/server-status", "debug", rb"(?i)apache server status", "medium", "Debug endpoint publicly reachable"),
    ("/actuator/env", "debug", None, "medium", "Debug endpoint publicly reachable"),
    ("/wp-login.php", "admin_panel", rb"(?i)wordpress", "low", "Administrative interface publicly reachable"),
    ("/wp-admin/", "admin_panel", rb"(?i)wordpress", "low", "Administrative interface publicly reachable"),
    ("/phpmyadmin/", "admin_panel", rb"(?i)phpmyadmin", "low", "Administrative interface publicly reachable"),
    ("/administrator/", "admin_panel", rb"(?i)administrator", "low", "Administrative interface publicly reachable"),
)
REDIRECT_PARAMS = ("next", "redirect", "redirect_uri", "return", "returnUrl", "url", "continue", "dest")
SOURCE_MAP_SIGNATURE = rb'^\s*\{(?=[\s\S]*"version"\s*:\s*3\s*[,}])(?=[\s\S]*"(?:sources|mappings)"\s*:)'
SENSITIVE_KEYS = re.compile(
    rb"\"(env|environment|database|db|dbHost|host|hostname|version|commit|uptime|memory|heap|nodeVersion|"
    rb"node_version|secret|password|stack|config|redis|connectionString)\"\s*:",
    re.IGNORECASE,
)
DEBUG_SIGNATURE = re.compile(rb"\"(env|config|stack|process|headers|secret|password|database)\"\s*:", re.IGNORECASE)
SCRIPT = re.compile(rb"<script[^>]+src=\"(/_next/static/[A-Za-z0-9_\-./~]+\.js)(?:\?[^\"]*)?\"")
IMPACT = {
    "secret_file": "Environment files usually hold database passwords, API keys and signing secrets.",
    "vcs": "Git metadata can let anyone rebuild the source code and its history, including removed secrets.",
    "debug": "Debug endpoints can reveal configuration, environment details or internal state.",
    "health": "Detailed health output reveals internal components and versions that help target attacks.",
    "api_docs": "Public API documentation maps every endpoint and parameter for an attacker.",
    "source_map": "Source maps reveal the original front-end source, comments and internal API paths.",
    "backup_file": "Backup archives and database dumps usually contain the same secrets and customer data as production.",
    "config_file": "Deployment configuration files can disclose internal hostnames, ports and sometimes embedded secrets.",
    "admin_panel": "An administrative interface reachable by anyone is a direct target for credential attacks.",
    "cors": "Any website can read authenticated API responses on behalf of a logged-in visitor.",
    "open_redirect": "A crafted link to this trusted domain can silently send visitors to an attacker's site, commonly used to make phishing links look legitimate.",
}
REMEDIATION = {
    "secret_file": "Remove the file from the deployed image, rotate every secret it contained, and block dotfiles.",
    "vcs": "Exclude .git from the build context and block dotfile paths at the server or load balancer.",
    "debug": "Remove debug endpoints from deployed builds or require administrator authentication.",
    "health": "Return only a minimal status (for example {\"status\":\"ok\"}) on unauthenticated health checks.",
    "api_docs": "Restrict API documentation to authenticated staff or remove it from production builds.",
    "source_map": "Disable productionBrowserSourceMaps or upload maps privately to your error tracker instead.",
    "backup_file": "Remove the backup from the public web root; store backups outside it, encrypted and access-controlled.",
    "config_file": "Remove the file from the deployed image and keep deployment config out of the web root.",
    "admin_panel": "Confirm the interface requires strong authentication, or restrict it to a trusted network or VPN.",
    "cors": "Stop reflecting arbitrary Origin values; return a fixed, trusted origin (or none) whenever credentials are allowed.",
    "open_redirect": "Validate redirect targets against an allowlist of paths or domains before issuing a redirect.",
}


def content_class(headers: dict[str, list[str]]) -> str:
    value = (headers.get("content-type") or [""])[0].split(";")[0].strip().lower()
    if value == "text/html":
        return "html"
    if value in ("application/json", "application/javascript", "text/javascript") or value.endswith("+json"):
        return "json" if "json" in value else "javascript"
    if value.startswith("text/"):
        return "text"
    return "binary" if value else "none"


def length(headers: dict[str, list[str]]) -> int | None:
    try:
        return int((headers.get("content-length") or [""])[0])
    except ValueError:
        return None


def looks_like_baseline(status: int, headers: dict, baseline: dict) -> bool:
    """True when a response matches what the server returns for a path that cannot exist."""
    if status != baseline["status"] or content_class(headers) != baseline["content_class"]:
        return False
    a, b = length(headers), baseline["length"]
    return a is None or b is None or abs(a - b) <= max(64, b // 20)


def candidate(kind: str, status: int, headers: dict, baseline: dict) -> bool:
    if not 200 <= status < 300 or looks_like_baseline(status, headers, baseline):
        return False
    cls = content_class(headers)
    if kind in ("secret_file", "vcs", "backup_file", "config_file"):
        return cls in ("text", "binary", "none")
    if kind == "health":
        return cls == "json"
    if kind == "debug":
        return cls in ("json", "html", "text")
    if kind == "source_map":
        return cls in ("json", "binary", "text", "none")
    if kind == "admin_panel":
        return cls == "html"
    return cls != "none"


def signature_matches(kind: str, pattern, body: bytes) -> bool:
    if kind == "health":
        return len(set(match.lower() for match in SENSITIVE_KEYS.findall(body))) >= 2
    if kind == "debug" and pattern is None:
        return bool(DEBUG_SIGNATURE.search(body))
    if pattern is None:
        return False
    return bool(re.search(pattern, body))


def finding(path: str, kind: str, severity: str, title: str, confirmed: bool, note: str) -> dict:
    return {
        "title": title, "severity": severity if confirmed else ("medium" if severity == "high" else severity),
        "verification": "confirmed" if confirmed else "suspected",
        "category": "data_exposure" if kind in ("secret_file", "vcs", "source_map", "backup_file") else "configuration",
        "owasp": "A02",
        "path": path, "impact": IMPACT[kind], "remediation": REMEDIATION[kind], "evidence": note[:300],
    }


def run(config: dict, approval: dict, host: str, headers: dict, request, expires_at, pause,
        *, records=None, findings=None, on_homepage=None, on_links=None) -> tuple[list, list]:
    """Return (records, findings). `request` is assessment.request; `pause` sleeps between calls."""
    excluded = config["scope"]["excluded_prefixes"]
    timeout = approval.get("request_timeout_seconds", 10)
    records = [] if records is None else records
    findings = [] if findings is None else findings

    def call(method, path, extra=None, limit=0):
        from .assessment import stop_on_http
        pause()
        result = request(host, method, path, headers={**headers, **(extra or {})}, expires_at=expires_at,
                         timeout_seconds=timeout, body_limit=limit)
        stop_on_http(path, result[0])
        return result

    probe = "/mvk-baseline-" + secrets.token_hex(8)
    if any(probe.startswith(prefix) for prefix in excluded):
        from .process import ToolError
        raise ToolError("Random baseline path is excluded; exposure checks stopped.")
    status, received, _ = call("HEAD", probe)
    baseline = {"status": status, "content_class": content_class(received), "length": length(received)}
    records.append({"path": "/mvk-baseline-{random}", "kind": "baseline", "status": status, "exposed": False, "signature": None})

    def check(path, kind, pattern, severity, title):
        if any(path.startswith(prefix) for prefix in excluded):
            return
        status, received, _ = call("HEAD", path)
        exposed = candidate(kind, status, received, baseline)
        signature = None
        if exposed:
            get_status, get_headers, body = call("GET", path, {"Range": "bytes=0-2047"}, limit=2048)
            signature = (candidate(kind, get_status, get_headers, baseline)
                         and signature_matches(kind, pattern, body))
            exposed = bool(signature)
        records.append({"path": path, "kind": kind, "status": status, "exposed": exposed, "signature": signature})
        if exposed:
            note = "HEAD was reachable and GET content signature matched in the first 2 KB; content was not stored."
            confirmed = kind in ("secret_file", "vcs", "source_map", "backup_file")
            findings.append(finding(path, kind, severity, title, confirmed, note))

    for path, kind, pattern, severity, title in CHECKS:
        check(path, kind, pattern, severity, title)

    if not any("/".startswith(prefix) for prefix in excluded):
        status, received, body = call("GET", "/", limit=262144)
        if on_homepage is not None and 200 <= status < 300:
            on_homepage(received, body)
        from .headers import cors_misconfigured

        probe_origin = f"https://mvk-cors-{secrets.token_hex(8)}.invalid"
        cors_status, cors_headers, _ = call("GET", "/", {"Origin": probe_origin})
        if 200 <= cors_status < 300 and cors_misconfigured(probe_origin, cors_headers):
            records.append({"path": "/", "kind": "cors", "status": cors_status, "exposed": True, "signature": True})
            findings.append(finding(
                "/", "cors", "high", "Cross-origin requests with credentials are allowed from any origin", True,
                "The Access-Control-Allow-Origin header reflected a random, never-before-seen origin while "
                "Access-Control-Allow-Credentials was true; no request body or cookie value was stored.",
            ))
        marker = f"mvk-redirect-{secrets.token_hex(8)}.invalid"
        for param in REDIRECT_PARAMS:
            probe_path = f"/?{param}=https%3A%2F%2F{marker}%2F"
            try:
                pause()
                redirect_status, redirect_headers, _ = request(
                    host, "GET", probe_path, headers=headers, expires_at=expires_at, timeout_seconds=timeout,
                )
            except (OSError, TimeoutError):
                continue
            # Deliberately does not go through call()/stop_on_http: a 3xx here is the signal being
            # looked for, not a reason to stop, and any other status (401/403/429/5xx included) from
            # a guessed query parameter the app may not even read is "nothing found", same as every
            # other best-effort probe in recon.py - not an assessment failure.
            location = (redirect_headers.get("location") or [""])[0]
            if 300 <= redirect_status < 400 and marker in location:
                records.append({"path": probe_path, "kind": "open_redirect", "status": redirect_status,
                                "exposed": True, "signature": True})
                findings.append(finding(
                    probe_path, "open_redirect", "medium",
                    "Unvalidated redirect target lets a crafted link send visitors off-site", True,
                    f"Requesting {probe_path} returned HTTP {redirect_status} with a Location header "
                    "pointing at a random, never-before-seen external domain; no real external site was contacted.",
                ))
                break
        scripts = []
        if 200 <= status < 300 and content_class(received) == "html":
            scripts = list(dict.fromkeys(match.decode() for match in SCRIPT.findall(body)))[:3]
        for script in scripts:
            if ".." not in script and len(script) < 200:
                check(script + ".map", "source_map", SOURCE_MAP_SIGNATURE, "low", "JavaScript source map publicly downloadable")

        if on_links is not None and 200 <= status < 300 and content_class(received) == "html":
            from . import recon

            confirmed = []
            for link in recon.extract_same_origin_links(host, body)[:10]:
                if any(link.startswith(prefix) for prefix in excluded):
                    continue
                try:
                    pause()
                    link_status, _, _ = request(
                        host, "HEAD", link, headers=headers, expires_at=expires_at, timeout_seconds=timeout,
                    )
                except (OSError, TimeoutError):
                    continue
                # Same convention as the redirect probe above: a broken or blocked linked page is
                # "nothing found," not a reason to stop the rest of the exposure scan - this is
                # confirming crawl candidates are real pages, not testing them for vulnerabilities.
                if 200 <= link_status < 300:
                    confirmed.append(link)
            on_links(confirmed)
    return records, findings
