"""Task-specific prerequisite checks without cloud authentication or target requests."""
import os
import shutil
import sys

PROFILES = ("html", "pdf", "roles", "iap-browser", "iap-keyless", "push", "local-tests")


def browser_check(headless: bool) -> tuple[bool, str]:
    try:
        from playwright.sync_api import Error as BrowserError, sync_playwright
    except ImportError:
        return False, "Install the report extra and Playwright Chromium."
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=headless,
                args=["--no-startup-window"] if not headless else [],
            )
            browser.close()
    except BrowserError:
        return False, "Chromium could not launch; check its installation, system libraries and display access."
    return True, "Chromium launched and closed locally; no page or login was opened."


def diagnose(profile: str, config: dict | None = None) -> dict:
    checks = []
    def check(name, ready, detail):
        checks.append({"name": name, "ready": ready, "detail": detail})
    def executable(name):
        found = shutil.which(name) is not None
        check(name, found, "Executable available." if found else f"Install {name} and make it available on PATH.")

    check("python", sys.version_info >= (3, 11), "Python 3.11 or newer is required.")
    gateway = config.get("access", {}).get("type") if config else None
    if profile == "roles" and config is not None:
        check("role_adapter", config.get("role_testing", {}).get("adapter") == "dtap-cookie-v1",
              "A configured DTAP role adapter is required; credentials and scope are not checked here.")
    if profile == "push":
        executable("git")
        executable("docker")
    if profile == "local-tests":
        executable("git")
        executable("openssl")
    if profile == "iap-keyless" or (profile == "roles" and gateway == "iap-service-account"):
        executable("gcloud")
    needs_browser = profile in ("pdf", "iap-browser") or (profile == "roles" and gateway == "iap-browser")
    headed = profile == "iap-browser" or (profile == "roles" and gateway == "iap-browser")
    if needs_browser:
        display = sys.platform != "linux" or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if headed:
            check("display", display, "Interactive IAP requires access to a graphical desktop.")
        if not headed or display:
            ready, detail = browser_check(headless=not headed)
            check("chromium", ready, detail)
    notes = [
        "No application requests, cloud authentication, credential reads or package installations were performed.",
        "This checks local prerequisites, not authorization or permission to assess a target.",
    ]
    if profile == "push":
        notes.append("The Docker daemon and scanner images are not checked here; vapt check validates them.")
    if profile == "roles":
        notes.append("QA emails/passwords and active approval are required at run time, not read by doctor.")
        if config is None:
            notes.append("No project configuration supplied; gateway prerequisites were not checked. Use --config.")
        elif gateway == "bearer":
            check("gateway", False, "Arbitrary bearer access is not supported by the role runner.")
    if profile == "local-tests":
        notes.append("Optional browser, Docker and external-app labs require their separate prerequisites.")
    if profile == "iap-keyless" or gateway == "iap-service-account":
        notes.append("gcloud login, IAM signing permissions and IAP access are not verified by this offline check.")
    return {"profile": profile, "ready": all(item["ready"] for item in checks), "checks": checks, "notes": notes}
