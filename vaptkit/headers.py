"""Deterministic grading of security response headers.

Rules are deliberately conservative: a check fails only when the header value is
known to be weak in current browsers, so findings stay accurate.
"""
import re

HSTS_MIN_SECONDS = 15552000  # 180 days, the common minimum used by public graders
SESSION_COOKIE = re.compile(r"(sess|sid|auth|token|jwt|login|bind)", re.IGNORECASE)
WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}
REFERRER_POLICIES = WEAK_REFERRER | {
    "no-referrer", "same-origin", "origin", "strict-origin", "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
}
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
    has_nonce_or_hash = any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_-]+=*'", token)
                            for token in sources)
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        weaknesses.append("'unsafe-inline'")
    if "'unsafe-eval'" in sources:
        weaknesses.append("'unsafe-eval'")
    if "'strict-dynamic'" not in sources or not has_nonce_or_hash:
        for wildcard in ("*", "http:", "https:", "data:"):
            if wildcard in sources:
                weaknesses.append(wildcard)
    if "object-src" not in directives and "default-src" not in directives:
        weaknesses.append("no object-src")
    for directive in ("script-src-elem", "script-src-attr"):
        if directive in directives:
            override = directives[directive]
            nonce = any(re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_-]+=*'", token)
                        for token in override)
            if "'unsafe-inline'" in override and (directive == "script-src-attr" or not nonce):
                weaknesses.append(f"{directive} permits inline scripts")
            if directive == "script-src-elem" and not ("'strict-dynamic'" in override and nonce):
                if any(token in ("*", "http:", "https:", "data:") for token in override):
                    weaknesses.append(f"{directive} permits broad sources")
    return weaknesses


def hsts_strong(value: str) -> bool:
    values = []
    for directive in value.split(";"):
        if directive.strip().split("=", 1)[0].strip().lower() != "max-age":
            continue
        match = re.fullmatch(r'\s*max-age\s*=\s*(?:"([0-9]{1,20})"|([0-9]{1,20}))\s*',
                             directive, re.IGNORECASE)
        if not match:
            return False
        values.append(int(match.group(1) or match.group(2)))
    return len(values) == 1 and values[0] >= HSTS_MIN_SECONDS


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


def cors_misconfigured(probe_origin: str, headers: dict[str, list[str]]) -> bool:
    """True only for the classic exploitable combination: Access-Control-Allow-Origin reflects an
    arbitrary, attacker-chosen origin while Access-Control-Allow-Credentials is true - that lets
    any website read authenticated responses on behalf of a logged-in visitor. A bare wildcard
    with no credentials is common and intentional for public APIs, so it is deliberately not
    flagged, keeping this check as accurate as the rest of headers.py.
    """
    allow_origin = (headers.get("access-control-allow-origin") or [""])[0].strip()
    allow_credentials = (headers.get("access-control-allow-credentials") or [""])[0].strip().lower() == "true"
    return allow_origin == probe_origin and allow_credentials


def grade(headers: dict[str, list[str]]) -> dict[str, bool]:
    """Grade lower-cased header names mapped to all of their values."""
    def first(name):
        return (headers.get(name) or [""])[0]

    policies = [value.strip() for header in headers.get("content-security-policy", [])
                for value in header.split(",") if value.strip()]
    csp, hsts, xfo = first("content-security-policy"), first("strict-transport-security"), first("x-frame-options")
    referrers = [value.strip().lower() for header in headers.get("referrer-policy", [])
                 for value in header.split(",") if value.strip().lower() in REFERRER_POLICIES]
    referrer = referrers[-1] if referrers else ""
    server, powered = first("server"), first("x-powered-by")
    cookies_secure, cookies_httponly = cookie_flags(headers.get("set-cookie", []))
    return {
        "html_response": "text/html" in first("content-type").lower(),
        "hsts_present": bool(hsts),
        "csp_present": bool(csp),
        "nosniff": first("x-content-type-options").strip().lower() == "nosniff",
        "frame_policy_present": bool(xfo) or any("frame-ancestors" in csp_directives(policy) for policy in policies),
        "hsts_strong": hsts_strong(hsts),
        "csp_script_strong": any(not csp_script_weaknesses(policy) for policy in policies),
        "frame_policy_strong": (
            any(frame_strong("", policy) for policy in policies if "frame-ancestors" in csp_directives(policy))
            if any("frame-ancestors" in csp_directives(policy) for policy in policies) else frame_strong(xfo, "")
        ),
        "referrer_policy_safe": referrer not in WEAK_REFERRER,
        "cookies_secure": cookies_secure,
        "session_cookies_httponly": cookies_httponly,
        "no_version_disclosure": not powered and not VERSION_DIGITS.search(server),
    }
