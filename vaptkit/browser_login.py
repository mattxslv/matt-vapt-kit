import hashlib
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit

from .process import ToolError


def iap_cookie_header(cookies: list[dict]) -> str:
    selected = []
    for cookie in cookies:
        name = cookie.get("name", "")
        if not re.fullmatch(r"(?:__Host-)?GCP_IAP_AUTH_TOKEN_[A-Za-z0-9_-]+", name):
            continue
        value = cookie.get("value", "")
        if not cookie.get("secure") or not re.fullmatch(r"[A-Za-z0-9._~+/%=-]+", value):
            raise ToolError("IAP cookie has invalid attributes; value withheld.")
        selected.append(f"{name}={value}")
    header = "; ".join(selected)
    if len(header) > 16384:
        raise ToolError("IAP cookie exceeds the request limit; value withheld.")
    return header


def login_request_allowed(url: str, method: str, origin: str, excluded: list[str]) -> bool:
    try:
        parsed = urlsplit(url)
        target = urlsplit(origin)
        if parsed.scheme != "https" or parsed.port not in (None, 443):
            return False
    except ValueError:
        return False
    if parsed.hostname == target.hostname:
        path = unquote(parsed.path)
        if path.startswith("//") or "\\" in path or any(part in (".", "..") for part in path.split("/")):
            return False
        if any(path.startswith(prefix) for prefix in excluded):
            return False
        return method in ("GET", "HEAD") or (method == "POST" and path.startswith("/_gcp_iap/"))
    host = parsed.hostname or ""
    return (
        host in ("accounts.google.com", "www.google.com", "accounts.youtube.com")
        or host.endswith(".gstatic.com")
        or host.endswith(".googleapis.com")
    )


def profile_directory(origin: str) -> Path:
    state_root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
    if not state_root.is_absolute():
        raise ToolError("XDG_STATE_HOME must be an absolute path for saved login state.")
    root = state_root / "matt-vapt-kit" / "iap-browser"
    profile = root / hashlib.sha256(origin.encode()).hexdigest()[:24]
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.parent.chmod(0o700)
    root.chmod(0o700)
    profile.chmod(0o700)
    return profile


def login(config: dict, approval: dict, *,
          validate_scope: Callable[[dict, dict], None] | None = None) -> dict[str, str]:
    from .assessment import public_addresses, utc, validate_approval
    validate_scope = validate_scope or validate_approval
    validate_scope(config, approval)
    try:
        from playwright.sync_api import Error as BrowserError, sync_playwright
    except ImportError:
        raise ToolError("Install matt-vapt-kit[report] and Playwright Chromium for manual IAP login.") from None
    origin = config["target"]["url"].rstrip("/")
    public_addresses(urlsplit(origin).hostname)
    remaining = (utc(approval["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
    deadline = time.monotonic() + min(300, remaining)
    remember = config["access"].get("remember_login", False)
    print("Opening the toolkit browser. Sign in with your authorized govmail if prompted; never enter credentials in this terminal.", flush=True)
    print(
        "Dedicated private browser profile enabled; Google login cookies may persist on this PC."
        if remember else "Temporary browser: login state will not be saved.",
        flush=True,
    )
    try:
        with sync_playwright() as playwright:
            browser = None
            if remember:
                context = playwright.chromium.launch_persistent_context(
                    str(profile_directory(origin)), headless=False,
                    service_workers="block", accept_downloads=False,
                )
            else:
                browser = playwright.chromium.launch(headless=False)
                context = browser.new_context(service_workers="block", accept_downloads=False)
            try:
                def route_request(route):
                    request = route.request
                    if (time.monotonic() < deadline
                            and login_request_allowed(request.url, request.method, origin, config["scope"]["excluded_prefixes"])):
                        route.continue_()
                    else:
                        route.abort()

                context.route("**/*", route_request)
                validate_scope(config, approval)
                cookie = iap_cookie_header(context.cookies(origin + "/"))
                if cookie:
                    print("Reusing the saved target IAP session; no new sign-in needed.", flush=True)
                    return {"Cookie": cookie}
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(origin + "/", wait_until="domcontentloaded", timeout=30000)
                while time.monotonic() < deadline:
                    if page.is_closed():
                        raise ToolError("Login window closed before IAP authentication completed.")
                    validate_scope(config, approval)
                    # Playwright filters by the exact target URL; never collect Google cookies.
                    cookie = iap_cookie_header(context.cookies(origin + "/"))
                    if cookie:
                        print("Target IAP session acquired; closing login window before scoped assessment requests.", flush=True)
                        return {"Cookie": cookie}
                    page.wait_for_timeout(500)
                raise ToolError("Manual IAP login timed out; no assessment requests sent.")
            finally:
                context.close()
                if browser is not None:
                    browser.close()
    except BrowserError:
        raise ToolError("Browser login failed or was closed. Ensure Chromium is installed and no other toolkit process is using this profile; raw details withheld.") from None
