"""HTML/PDF report for a committed-code repository scan (.private/scan-* folder)."""
import json
from datetime import datetime
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

from .assessment import write_private
from .process import ToolError
from .report import FORMAT_ID, PHT, TLP_COLOR, esc

STATUS_CLASS = {"DONE": "sev-low", "REVIEW": "sev-high", "NOT RUN": "sev-medium", "CANCELLED": "sev-medium"}
TABLE_LIMIT = 300


def read(folder: Path, name: str) -> dict | None:
    path = folder / name
    return json.loads(path.read_text()) if path.is_file() else None


def stage(row: dict) -> str:
    return row["check"].split("  ", 1)[-1]


def table(headers: tuple, rows: list[tuple], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows[:TABLE_LIMIT])
    more = f'<p class="muted">{len(rows) - TABLE_LIMIT} more not shown; see the JSON evidence.</p>' if len(rows) > TABLE_LIMIT else ""
    return f'<table class="info-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}'


def render_scan(folder: Path, *, tlp: str = "AMBER+STRICT") -> str:
    summary = read(folder, "summary.json")
    if summary is None or summary.get("kind") != "repository-scan":
        raise ToolError("No repository scan summary in this folder.")
    static = read(folder, "static-findings.json") or {}
    routes = read(folder, "route-review.json") or {}
    facts = summary.get("facts", {})
    project = summary.get("project") or routes.get("project") or folder.name
    finished = datetime.fromisoformat(summary["finished_at"]).astimezone(PHT) if summary.get("finished_at") else None
    when = finished.strftime("%B %d, %Y %I:%M %p PHT") if finished else "Unknown"
    rid = f"MVK-SCAN-{folder.name.removeprefix('scan-')}"
    css = files("vaptkit").joinpath("assets/report.css").read_text()

    checks = table(("Check", "Status", "Detail"), [
        (esc(stage(row)), f'<span class="sev {STATUS_CLASS.get(row["status"], "sev-medium")}">{esc(row["status"])}</span>',
         esc(row["detail"]))
        for row in summary["checks"]
    ], "No checks recorded.")
    leaks = facts.get("leaks")
    leak_text = (f"{leaks} possible secrets were found in the Git history. Values are redacted and not stored. "
                 "Rotate any real credential, then add reviewed false positives to .gitleaksignore."
                 if leaks else "No possible secrets were reported, or the count was not recorded for this scan.")
    static_rows = [(esc(item["rule"]), f'<code>{esc(item["path"])}</code>', esc(item["line"]))
                   for item in static.get("findings", [])]
    route_rows = [
        (f'<code>{esc(route["path"])}</code>', esc(handler["method"]), f'<code>{esc(route.get("file", ""))}</code>')
        for route in routes.get("routes", []) for handler in route["handlers"] if not handler["authentication"]
    ]
    not_tested = "".join(f"<li>{esc(item)}</li>" for item in summary.get("not_tested", []))
    kit_version = esc(version("matt-vapt-kit"))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{esc(rid)} | {esc(project)} Repository Scan</title><style>{css}</style></head><body>
<div class="watermark" aria-hidden="true">MATT VAPT KIT | REPOSITORY SCAN</div>
<main>
<section class="cover">
  <div class="mvk-ribbon">MATT VAPT KIT | INTERNAL REPOSITORY SCAN | NOT ISSUED BY CERT-PH</div>
  <div class="cover-mark"><span class="mvk-badge">MVK</span><span>Matt VAPT Kit</span></div>
  <p class="cover-kicker">COMMITTED-CODE SECURITY SCAN</p>
  <h1>{esc(project)}<span>Repository Scan</span></h1>
  <p class="cover-target">Commit {esc(summary["revision"][:12])}</p>
  <dl class="cover-meta">
    <div><dt>Date of Scan</dt><dd>{esc(when)}</dd></div>
    <div><dt>Report ID</dt><dd>{esc(rid)}</dd></div>
    <div><dt>Classification</dt><dd><span class="tlp" style="color:{TLP_COLOR[tlp]}">TLP:{esc(tlp)}</span></dd></div>
  </dl>
  <p class="cover-note">This is not a CERT-PH report, a penetration test or an all-clear. It covers committed
  code only; findings are suspected until a person confirms them.</p>
</section>

<section id="s1" class="chapter">
  <h2>1 SUMMARY</h2>
  <p>{esc(summary.get("recap") or "No plain-English recap was recorded for this scan.")}</p>
  {checks}
</section>

<section id="s2" class="chapter">
  <h2>2 SECRETS IN GIT HISTORY</h2>
  <p>{esc(leak_text)}</p>
</section>

<section id="s3" class="chapter">
  <h2>3 STATIC RULE MATCHES</h2>
  <p>Pattern matches in the committed tree. Source lines are intentionally not reproduced.</p>
  {table(("Rule", "File", "Line"), static_rows, "No static-rule matches were recorded.")}
</section>

<section id="s4" class="chapter">
  <h2>4 API ROUTES WITHOUT AN AUTHENTICATION CHECK</h2>
  <p>Handlers where no session or token check was found in code. Middleware may still protect some of them;
  confirm each one before treating it as a vulnerability.</p>
  {table(("Route", "Method", "File"), route_rows, "No unauthenticated API handlers were reported.")}
</section>

<section id="s5" class="chapter">
  <h2>5 SCOPE AND LIMITATIONS</h2>
  <p>Not tested by this scan:</p><ul>{not_tested}</ul>
</section>
</main>
<footer class="screen-footer">{FORMAT_ID} v{kit_version} | {esc(rid)} | Matt VAPT Kit repository scan</footer>
</body></html>"""


def write_scan_report(folder: Path, *, html_only: bool = False, tlp: str = "AMBER+STRICT") -> tuple[Path, Path | None]:
    """Write report.html (and report.pdf unless html_only or the PDF tools are missing) into the scan folder."""
    document = render_scan(folder, tlp=tlp)
    html_path = folder / "report.html"
    write_private(html_path, document)
    if html_only:
        return html_path, None
    return html_path, print_pdf(document, folder / "report.pdf",
                                footer=f"{FORMAT_ID} | Matt VAPT Kit repository scan", tlp=tlp)


def pdf_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


def print_pdf(document: str, destination: Path, *, footer: str, tlp: str) -> Path | None:
    """Print HTML to PDF with headless Chromium; None if the PDF tools aren't installed."""
    if not pdf_available():
        return None
    from playwright.sync_api import Error as BrowserError, sync_playwright
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            try:
                context = browser.new_context()
                context.route("**/*", lambda route: route.abort())
                page = context.new_page()
                page.set_content(document, wait_until="load")
                pdf = page.pdf(
                    format="A4", print_background=True, prefer_css_page_size=True, tagged=True, outline=True,
                    display_header_footer=True,
                    header_template=(
                        '<div style="font-size:8px;width:100%;padding:0 18mm;color:#3b4a5c;'
                        'display:flex;justify-content:space-between"><span>Repository Scan | Self-Assessment</span>'
                        f'<span style="font-weight:700;color:{TLP_COLOR[tlp]}">TLP:{esc(tlp)}</span></div>'
                    ),
                    footer_template=(
                        '<div style="font-size:7.5px;width:100%;padding:0 18mm;color:#526374;'
                        f'display:flex;justify-content:space-between"><span>{esc(footer)}</span>'
                        '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
                    ),
                )
            finally:
                browser.close()
    except BrowserError:
        raise ToolError("Chromium could not print the PDF (it may be missing system libraries); "
                        "the HTML report was saved.") from None
    write_private(destination, pdf)
    return destination
