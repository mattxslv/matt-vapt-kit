import base64
import hashlib
import html
import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from .assessment import create_output, load_json, write_private
from .process import ToolError

PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CHECK_LABELS = {
    "html_response": "HTML page response",
    "hsts_present": "HTTPS-only browser policy (HSTS)",
    "csp_present": "Browser script policy (CSP)",
    "nosniff": "Protection against guessing file types",
    "frame_policy_present": "Restrictions on embedding this page",
}


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def validate_result(result: dict) -> None:
    schema = json.loads(files("vaptkit").joinpath("schemas/report.json").read_text())
    if next(Draft202012Validator(schema).iter_errors(result), None) is not None:
        raise ToolError("Report input does not match the assessment schema; contents withheld.")
    if result["status"] == "completed":
        paths = [item["path"] for item in result["observations"]]
        if (result["errors"] or not paths or paths != result["approved_paths"]
                or any(not 200 <= item["status"] < 300 for item in result["observations"])):
            raise ToolError("A completed report must contain a successful observation for every approved path and no errors.")
    if result["profile"] in ("unauthenticated-head-only", "bearer-head-only", "iap-browser-head-only") and (
        result["coverage"]["data_exposure"] != "not_tested"
        or result["coverage"]["unauthorized_access"] != "not_tested"
    ):
        raise ToolError("HEAD-only profiles cannot claim data-exposure or access-control test coverage.")


def conclusion(result: dict, category: str) -> str:
    findings = [finding for finding in result["findings"] if finding["category"] == category]
    if any(finding["verification"] == "confirmed" for finding in findings):
        return "Confirmed"
    if findings:
        return "Suspected"
    if result["status"] == "incomplete" or result["coverage"][category] == "not_tested":
        return "Not tested"
    return "Not observed in tested scope"


def render(result: dict, screenshots=()) -> str:
    validate_result(result)
    css = files("vaptkit").joinpath("assets/report.css").read_text()
    findings = sorted(result["findings"], key=lambda item: PRIORITY[item["severity"]])
    finding_html = []
    for index, finding in enumerate(findings, 1):
        finding_html.append(f"""
        <article class="finding">
          <div class="severity {esc(finding['severity'])}">{index:02d} / {esc(finding['severity'])} / {esc(finding['verification'])}</div>
          <h3>{esc(finding['title'])}</h3>
          <p><span class="field">Affected path:</span> <code>{esc(finding['path'])}</code></p>
          <p><span class="field">What this means:</span> {esc(finding['impact'])}</p>
          <p><span class="field">What to do:</span> {esc(finding['remediation'])}</p>
          <p class="muted">Retest: not recorded. No CVSS score assigned.</p>
        </article>""")
    evidence = []
    for index, observation in enumerate(result["observations"], 1):
        assessable = 200 <= observation["status"] < 300
        rows = "".join(
            f"<tr><td>{esc(CHECK_LABELS[key])}</td><td>{('Observed' if value else 'Not observed') if assessable else 'Not assessed (non-2xx response)'}</td></tr>"
            for key, value in observation["checks"].items()
        )
        evidence.append(f"""
        <article class="evidence" id="evidence-{index}">
          <div class="label">Matt VAPT Kit / Rendered HTTP observation / E{index:02d}</div>
          <h3>{esc(observation['method'])} {esc(observation['path'])}</h3>
          <p>HTTP status: <strong>{observation['status']}</strong></p>
          <table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>
          <p class="muted">Response bodies, cookies and raw header values were not retained.
          Presence alone does not prove a policy is effective.</p>
        </article>""")
    images = "".join(
        f'<figure><img alt="Rendered observation E{index:02d}" src="data:image/png;base64,{data}">'
        f'<figcaption>E{index:02d}. Browser screenshot of the sanitized observation above, not the target page. '
        f'SHA-256: <code>{sha}</code></figcaption></figure>'
        for index, data, sha in screenshots
    )
    errors = "".join(
        f"<li><code>{esc(error['path'])}</code>: {esc(error['message'])}</li>"
        for error in result["errors"]
    )
    fixture = '<div class="warning"><strong>SYNTHETIC EXAMPLE.</strong> This is not a live assessment.</div>' if result["status"] == "fixture" else ""
    run_state = "Incomplete: review the stopped checks below." if result["status"] == "incomplete" else "Completed within the recorded scope." if result["status"] == "completed" else "Synthetic example only."
    next_action = "Review the observations below, verify impact, then record remediation and a retest." if findings else "No findings were recorded by these checks. Review untested areas before making a security decision."
    if result["status"] == "incomplete":
        next_action = "Assessment incomplete. Resolve the access or execution issue below before drawing conclusions about the application."
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
      <title>{esc(result['project'])} | Matt VAPT Kit</title><style>{css}</style></head><body><main>
      <header class="masthead"><span class="brand">matt / vapt kit</span><span class="label">Internal self-assessment / Restricted</span></header>
      {fixture}<h1>{esc(result['project'].upper())}<br>Security briefing</h1>
      <p class="lede">{esc(next_action)}</p>
      <dl class="meta"><div><dt>Target</dt><dd>{esc(result['target'])}</dd></div>
      <div><dt>Assessment window</dt><dd>{esc(result['started_at'])}<br>{esc(result['finished_at'])}</dd></div>
      <div><dt>Profile</dt><dd>{esc(result['profile'])}</dd></div><div><dt>Run status</dt><dd>{esc(run_state)}</dd></div></dl>
      <div class="summary">
        <div class="summary-row"><span>Was data exposure found?</span><strong class="status">{conclusion(result, 'data_exposure')}</strong></div>
        <div class="summary-row"><span>Was unauthorized access found?</span><strong class="status">{conclusion(result, 'unauthorized_access')}</strong></div>
      </div>
      <p class="muted">This is not a CERT-PH report or certification. A vulnerability assessment cannot establish that no historical data leak occurred.</p>
      <section><div class="label">01 / Action briefing</div><h2>What to review first</h2>
      {''.join(finding_html) or '<p>No findings recorded. This is not an all-clear.</p>'}</section>
      <section><div class="label">02 / Scope and limitations</div><h2>What this run can tell you</h2>
      <p>{esc(result['coverage']['note'])}</p><p>Approved paths: <code>{esc(', '.join(result['approved_paths']))}</code></p>
      <p>Redirects are not followed. Non-2xx responses are coverage gaps, not passing checks.</p>
      <p>Scope fingerprint: <code>{esc(result['scope_sha256'])}</code></p>
      {'<h3>Stopped or failed checks</h3><ul>' + errors + '</ul>' if errors else ''}</section>
      <section><div class="label">03 / Evidence record</div><h2>Observations you can inspect</h2>
      {''.join(evidence) or '<p>No HTTP observations were captured.</p>'}
      {images}</section>
      <footer>Matt VAPT Kit / Internal use only / Share only with authorized recipients.
      Screenshots supplement the searchable text. Sensitive text must be reviewed before export.</footer>
      </main></body></html>"""


def generate(source: Path, output: Path, *, reviewed: bool, html_only=False) -> Path:
    if not reviewed:
        raise ToolError("Review and redact the JSON first, then pass --reviewed. Automatic redaction cannot guarantee safety.")
    result = load_json(source)
    validate_result(result)
    if not html_only:
        try:
            from playwright.sync_api import Error as BrowserError, sync_playwright
        except ImportError:
            raise ToolError("Install matt-vapt-kit[report] and Playwright Chromium, or use --html-only.") from None
    create_output(output)
    document = render(result)
    if not html_only:
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    context = browser.new_context(viewport={"width": 1280, "height": 960}, device_scale_factor=1)
                    context.route("**/*", lambda route: route.abort())
                    page = context.new_page()
                    page.set_content(document, wait_until="load")
                    images = []
                    for index, locator in enumerate(page.locator(".evidence").all(), 1):
                        image = locator.screenshot()
                        write_private(output / f"evidence-{index:02d}.png", image)
                        images.append((index, base64.b64encode(image).decode(), hashlib.sha256(image).hexdigest()))
                    document = render(result, images)
                    page.set_content(document, wait_until="load")
                    pdf = page.pdf(
                        format="A4", print_background=True, prefer_css_page_size=True,
                        tagged=True, outline=True, display_header_footer=True,
                        header_template="<span></span>",
                        footer_template=(
                            '<div style="font-size:8px;width:100%;padding:0 16mm;color:#526374">'
                            'Matt VAPT Kit | Internal use only'
                            '<span style="float:right">Page <span class="pageNumber"></span>'
                            ' of <span class="totalPages"></span></span></div>'
                        ),
                    )
                    write_private(output / "report.pdf", pdf)
                finally:
                    browser.close()
        except BrowserError:
            raise ToolError("Browser export failed. Partial evidence may remain; install Chromium and retry in a new output directory.") from None
    destination = output / "report.html"
    write_private(destination, document)
    return destination
