"""Passive JWT structure checks: no signature verification, no extra network calls.

Decodes the header and payload of a bearer token the kit's own role testing already received
from a real, approved login and flags shapes that weaken the token regardless of what its
signature says (a missing expiry, an absurdly long lifetime, or an unsigned "none" algorithm).
This only reports what the issuer put in the token - it does not forge a token and resend it to
see whether a bypass would be accepted; that would be a separate, active test against a real
protected route, out of scope here.
"""
import base64
import json
import re

JWT_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
MAX_REASONABLE_LIFETIME_SECONDS = 30 * 24 * 3600  # 30 days

WEAKNESS_TITLES = {
    "alg_none": "Issued JWT uses the 'none' algorithm",
    "no_expiry": "Issued JWT has no expiry claim",
    "long_lived": "Issued JWT is valid for an unusually long time",
}
WEAKNESS_IMPACT = {
    "alg_none": "A token with algorithm 'none' is not cryptographically signed; anyone who can see its shape can forge one.",
    "no_expiry": "A token that never expires stays valid indefinitely if it leaks, with no automatic cutoff.",
    "long_lived": "A very long-lived token increases how long a leaked or stolen copy stays usable.",
}
WEAKNESS_REMEDIATION = {
    "alg_none": "Never issue or accept tokens signed with 'none'; enforce an explicit algorithm allowlist (for example RS256) on the verifier.",
    "no_expiry": "Issue tokens with a short, explicit 'exp' claim and use a refresh-token flow instead of a permanent token.",
    "long_lived": "Shorten the token lifetime and use a refresh-token flow for longer sessions.",
}
WEAKNESS_SEVERITY = {"alg_none": "critical", "no_expiry": "high", "long_lived": "medium"}


def decode_segment(segment: str) -> dict | None:
    """Base64url-decode and parse one JWT segment as a JSON object; None if it isn't one."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        value = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def looks_like_jwt(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 3 and all(part and JWT_SEGMENT.fullmatch(part) for part in parts[:2])


def jwt_weaknesses(token: str) -> list[str]:
    """Weakness codes found in a token's header/payload claims, decoded without verifying the
    signature. An opaque (non-JWT) token or one whose segments don't decode to JSON objects
    returns no weaknesses - this check only applies when the token is actually a JWT.
    """
    if not looks_like_jwt(token):
        return []
    header_part, payload_part, _ = token.split(".")
    header, payload = decode_segment(header_part), decode_segment(payload_part)
    if header is None or payload is None:
        return []
    weaknesses = []
    if str(header.get("alg", "")).strip().lower() in ("none", ""):
        weaknesses.append("alg_none")
    if "exp" not in payload:
        weaknesses.append("no_expiry")
    elif (isinstance(payload.get("exp"), (int, float)) and isinstance(payload.get("iat"), (int, float))
          and payload["exp"] - payload["iat"] > MAX_REASONABLE_LIFETIME_SECONDS):
        weaknesses.append("long_lived")
    return weaknesses
