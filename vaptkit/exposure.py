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
)
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
}
REMEDIATION = {
    "secret_file": "Remove the file from the deployed image, rotate every secret it contained, and block dotfiles.",
    "vcs": "Exclude .git from the build context and block dotfile paths at the server or load balancer.",
    "debug": "Remove debug endpoints from deployed builds or require administrator authentication.",
    "health": "Return only a minimal status (for example {\"status\":\"ok\"}) on unauthenticated health checks.",
    "api_docs": "Restrict API documentation to authenticated staff or remove it from production builds.",
    "source_map": "Disable productionBrowserSourceMaps or upload maps privately to your error tracker instead.",
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
    if kind in ("secret_file", "vcs"):
        return cls in ("text", "binary", "none")
    if kind in ("debug", "health"):
        return cls == "json"
    if kind == "source_map":
        return cls in ("json", "binary", "text", "none")
    return cls != "none"


def signature_matches(kind: str, pattern, body: bytes) -> bool:
    if kind == "health":
        return len(set(match.lower() for match in SENSITIVE_KEYS.findall(body))) >= 2
    if kind == "debug":
        return bool(DEBUG_SIGNATURE.search(body))
    if pattern is None:
        return False
    return bool(re.search(pattern, body))


def finding(path: str, kind: str, severity: str, title: str, confirmed: bool, note: str) -> dict:
    return {
        "title": title, "severity": severity if confirmed else ("medium" if severity == "high" else severity),
        "verification": "confirmed" if confirmed else "suspected",
        "category": "data_exposure" if kind in ("secret_file", "vcs", "source_map") else "configuration",
        "owasp": "A02",
        "path": path, "impact": IMPACT[kind], "remediation": REMEDIATION[kind], "evidence": note[:300],
    }


def run(config: dict, approval: dict, host: str, headers: dict, request, expires_at, pause,
        *, records=None, findings=None) -> tuple[list, list]:
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
            confirmed = kind in ("secret_file", "vcs", "source_map")
            findings.append(finding(path, kind, severity, title, confirmed, note))

    for path, kind, pattern, severity, title in CHECKS:
        check(path, kind, pattern, severity, title)

    if not any("/".startswith(prefix) for prefix in excluded):
        status, received, body = call("GET", "/", limit=262144)
        scripts = []
        if 200 <= status < 300 and content_class(received) == "html":
            scripts = list(dict.fromkeys(match.decode() for match in SCRIPT.findall(body)))[:3]
        for script in scripts:
            if ".." not in script and len(script) < 200:
                check(script + ".map", "source_map", SOURCE_MAP_SIGNATURE, "low", "JavaScript source map publicly downloadable")
    return records, findings
