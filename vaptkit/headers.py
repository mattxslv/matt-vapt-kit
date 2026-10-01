"""Deterministic grading of security response headers.

Rules are deliberately conservative: a check fails only when the header value is
known to be weak in current browsers, so findings stay accurate.
"""
import re

HSTS_MIN_SECONDS = 15552000  # 180 days, the common minimum used by public graders
SESSION_COOKIE = re.compile(r"(sess|sid|auth|token|jwt|login|bind)", re.IGNORECASE)
WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}
VERSION_DIGITS = re.compile(r"\d+\.\d+")


def csp_directives(value: str) -> dict[str, list[str]]:
    result = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens and tokens[0].lower() not in result:
            result[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    return result


def csp_script_weaknesses(value: str) -> list[str]:
    directives = csp_directives(value)
    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return ["no script-src or default-src"]
    weaknesses = []
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        weaknesses.append("'unsafe-inline'")
    if "'unsafe-eval'" in sources:
        weaknesses.append("'unsafe-eval'")
    if "'strict-dynamic'" not in sources:
        for wildcard in ("*", "http:", "https:", "data:"):
            if wildcard in sources:
                weaknesses.append(wildcard)
    if "object-src" not in directives and "default-src" not in directives:
        weaknesses.append("no object-src")
    return weaknesses


def hsts_strong(value: str) -> bool:
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    return bool(match) and int(match.group(1)) >= HSTS_MIN_SECONDS


def frame_strong(xfo: str, csp: str) -> bool:
    ancestors = csp_directives(csp).get("frame-ancestors")
    if ancestors is not None:
        return not any(source in ("*", "http:", "https:") for source in ancestors)
    return xfo.strip().lower() in ("deny", "sameorigin")


def cookie_flags(set_cookies: list[str]) -> tuple[bool, bool]:
    """Return (all cookies Secure, all session-like cookies HttpOnly). Values are never kept."""
    secure, httponly = True, True
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attributes = {part.strip().split("=", 1)[0].lower() for part in raw.split(";")[1:]}
        if "secure" not in attributes:
            secure = False
        if SESSION_COOKIE.search(name) and "httponly" not in attributes:
            httponly = False
    return secure, httponly


def grade(headers: dict[str, list[str]]) -> dict[str, bool]:
    """Grade lower-cased header names mapped to all of their values."""
    def first(name):
        return (headers.get(name) or [""])[0]

    csp, hsts, xfo = first("content-security-policy"), first("strict-transport-security"), first("x-frame-options")
    referrer = first("referrer-policy").split(",")[-1].strip().lower()
    server, powered = first("server"), first("x-powered-by")
    cookies_secure, cookies_httponly = cookie_flags(headers.get("set-cookie", []))
    return {
        "html_response": "text/html" in first("content-type").lower(),
        "hsts_present": bool(hsts),
        "csp_present": bool(csp),
        "nosniff": first("x-content-type-options").strip().lower() == "nosniff",
        "frame_policy_present": bool(xfo) or "frame-ancestors" in csp_directives(csp),
        "hsts_strong": hsts_strong(hsts),
        "csp_script_strong": bool(csp) and not csp_script_weaknesses(csp),
        "frame_policy_strong": frame_strong(xfo, csp),
        "referrer_policy_safe": referrer not in WEAK_REFERRER,
        "cookies_secure": cookies_secure,
        "session_cookies_httponly": cookies_httponly,
        "no_version_disclosure": not powered and not VERSION_DIGITS.search(server),
    }
