"""HTML/PDF report for a committed-code repository scan (.private/scan-* folder)."""
import json
from datetime import datetime
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

import yaml

from .assessment import write_private
from .brand import lockup_svg
from .process import ToolError
from .report import FORMAT_ID, PHT, TLP_COLOR, esc

STATUS = {"DONE": ("done", "Done"), "REVIEW": ("review", "Needs review"),
          "NOT RUN": ("gap", "Not run"), "CANCELLED": ("gap", "Cancelled")}
LOCATION_LIMIT = 120
ROUTE_LIMIT = 300


def read(folder: Path, name: str) -> dict | None:
    path = folder / name
    return json.loads(path.read_text()) if path.is_file() else None


def stage(row: dict) -> str:
    return row["check"].split("  ", 1)[-1]


def chip(status: str) -> str:
    kind, label = STATUS.get(status, ("gap", status.title()))
    return f'<span class="chip {kind}">{esc(label)}</span>'


def rule_messages() -> dict[str, str]:
    rules = yaml.safe_load(files("vaptkit").joinpath("rules/javascript.yml").read_text())
    return {f"rules.{rule['id']}": rule["message"] for rule in rules.get("rules", [])}


def next_steps(summary: dict, facts: dict, static_count: int, route_count: int) -> list[tuple[str, str]]:
    rows = {stage(row): row for row in summary["checks"]}
    steps = []
    if facts.get("leaks"):
        steps.append((f"Go through the {facts['leaks']} possible secrets in the Git history.",
                      "Rotate any credential that is real, even if it was later deleted, then add reviewed "
                      "false positives to .gitleaksignore."))
    audit = rows.get("Dependency audit")
    if audit and audit["status"] == "REVIEW":
        steps.append(("Update the vulnerable dependencies.", audit["detail"]))
    if route_count:
        steps.append((f"Check that {route_count} API handler{'s verify' if route_count != 1 else ' verifies'} the login.",
                      "No session or token check was found in their code. Add one inside the handler, or record "
                      "why the route is meant to be public."))
    if static_count:
        steps.append((f"Review {static_count} code-rule match{'es' if static_count != 1 else ''}.",
                      "Each is a pattern worth a second look, not a confirmed vulnerability. Section 3 groups them by rule."))
    for name, row in rows.items():
        if row["status"] in ("NOT RUN", "CANCELLED"):
            steps.append((f"{name} did not run, so it is not covered.", row["detail"]))
    if not steps:
        steps.append(("Nothing to fix from this scan.",
                      "Keep the weekly scan running. Live staging checks and manual review are still separate."))
    return steps


def render_scan(folder: Path, *, tlp: str = "AMBER+STRICT") -> str:
    summary = read(folder, "summary.json")
    if summary is None or summary.get("kind") != "repository-scan":
        raise ToolError("No repository scan summary in this folder.")
    static = read(folder, "static-findings.json") or {}
    routes = read(folder, "route-review.json") or {}
    facts = summary.get("facts", {})
    project = summary.get("project") or routes.get("project") or folder.name
    finished = datetime.fromisoformat(summary["finished_at"]).astimezone(PHT) if summary.get("finished_at") else None
    when = finished.strftime("%B %d, %Y · %I:%M %p PHT").replace(" 0", " ") if finished else "Unknown"
    rid = f"MVK-SCAN-{folder.name.removeprefix('scan-')}"
    kit_version = esc(version("matt-vapt-kit"))
    css = (files("vaptkit").joinpath("assets/scan-report.css").read_text()
           .replace("__TLP__", f"TLP:{tlp}")
           .replace("__FOOTER__", f"{FORMAT_ID} v{version('matt-vapt-kit')} · {rid} · Matt VAPT Kit repository scan"))

    # Same rule as the route review: public routes and empty stub handlers are not findings.
    unauthenticated = [(route, handler) for route in routes.get("routes", []) for handler in route["handlers"]
                       if not handler["authentication"] and not handler.get("public") and not handler.get("stub")]
    findings = static.get("findings", [])
    steps = "".join(f"<li><div><strong>{esc(title)}</strong><span>{esc(detail)}</span></div></li>"
                    for title, detail in next_steps(summary, facts, len(findings), len(unauthenticated)))
    checks = "".join(
        f'<tr><td class="check">{esc(stage(row))}</td><td class="state">{chip(row["status"])}</td>'
        f'<td>{esc(row["detail"])}</td></tr>' for row in summary["checks"])

    leaks = facts.get("leaks")
    history = next((row for row in summary["checks"] if stage(row) == "Secret history"), None)
    if leaks:
        secrets = (f'<p class="lede"><span class="count">{leaks}</span> possible secrets were found in the '
                   "commit history. The values are redacted and were never saved by the kit.</p>"
                   "<p>A secret stays exposed after it is deleted from the latest code, because every clone "
                   "still has the old commits. Treat each real one as leaked:</p><ul>"
                   "<li>Rotate or revoke it with the provider first.</li>"
                   "<li>Then decide whether the history needs rewriting.</li>"
                   "<li>Add reviewed false positives to <code>.gitleaksignore</code> so they stop reappearing.</li></ul>")
    elif history and history["status"] == "DONE":
        secrets = '<p class="lede">No possible secrets were found in the commit history.</p>'
    else:
        secrets = ('<p class="lede">The secret-history check did not finish cleanly, so this part is not covered. '
                   "See the table in section 1 and run the scan again.</p>")

    messages = rule_messages()
    grouped = {}
    for item in findings:
        grouped.setdefault(item["rule"], []).append(item)
    rule_sections = []
    for rule, items in sorted(grouped.items(), key=lambda pair: -len(pair[1])):
        locations = "".join(f'<li>{esc(item["path"])}<span class="line">:{esc(item["line"])}</span></li>'
                            for item in items[:LOCATION_LIMIT])
        more = (f'<p class="more">{len(items) - LOCATION_LIMIT} more locations are listed in static-findings.json.</p>'
                if len(items) > LOCATION_LIMIT else "")
        title = messages.get(rule, rule)
        rule_sections.append(
            f'<div class="rule-group"><div class="rule-head"><h3>{esc(title)}</h3>'
            f'<span class="count">{len(items)}</span></div><p class="rule-id mono">{esc(rule)}</p>'
            f'<ul class="locations">{locations}</ul>{more}</div>')
    static_html = "".join(rule_sections) or '<p class="lede">No code-rule matches were recorded.</p>'

    route_rows = "".join(
        f'<tr><td class="state"><span class="chip method">{esc(handler["method"])}</span></td>'
        f'<td><code>{esc(route["path"])}</code></td><td><code>{esc(route.get("file", ""))}</code></td></tr>'
        for route, handler in unauthenticated[:ROUTE_LIMIT])
    if unauthenticated:
        more = (f'<p class="more">{len(unauthenticated) - ROUTE_LIMIT} more are listed in route-review.json.</p>'
                if len(unauthenticated) > ROUTE_LIMIT else "")
        routes_html = ('<table><thead><tr><th>Method</th><th>Route</th><th>File</th></tr></thead>'
                       f"<tbody>{route_rows}</tbody></table>{more}")
    else:
        routes_html = '<p class="lede">Every API handler that was reviewed has an authentication check in code.</p>'

    staging = read(folder / "staging", "assessment.json")
    staging_html = ""
    if staging is not None:
        verification = {"confirmed": ("review", "Confirmed"), "suspected": ("gap", "Suspected"),
                        "observation": ("gap", "Observed")}
        rows = "".join(
            f'<tr><td class="check">{esc(item["title"])}</td><td class="state"><span class="chip '
            f'{verification.get(item["verification"], ("gap", ""))[0]}">'
            f'{esc(verification.get(item["verification"], ("gap", item["verification"]))[1])}</span></td>'
            f'<td><code>{esc(item.get("path", "/"))}</code></td></tr>' for item in staging["findings"])
        table_html = (f'<table><thead><tr><th>Finding</th><th>Status</th><th>Path</th></tr></thead><tbody>{rows}</tbody></table>'
                      if rows else '<p class="lede">Nothing was flagged on the pages checked.</p>')
        errors = (f'<p class="more">{len(staging["errors"])} requests did not complete, so those paths are not covered.</p>'
                  if staging["errors"] else "")
        staging_html = f"""<section class="chapter page">
  <header class="chapter-head"><p class="eyebrow">05</p><h2>Live staging checks</h2></header>
  <p class="lede">Read-only requests to <code>{esc(staging["target"])}</code>: security headers, cookies and a short list
  of commonly exposed files. No logins and no attack payloads. Confirmed means the same result was seen twice.</p>
  {table_html}{errors}
</section>
"""
    not_tested = "".join(f"<li>{esc(item[:1].upper() + item[1:])}</li>" for item in summary.get("not_tested", []))
    live_gap = "live staging" in summary.get("not_tested", [])
    covered = "".join(f"<li>{esc(stage(row))}</li>" for row in summary["checks"]
                      if row["status"] in ("DONE", "REVIEW")
                      and not (live_gap and stage(row).startswith("Live staging")))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{esc(rid)} | {esc(project)} Repository Scan</title><style>{css}</style></head><body>
<div class="watermark" aria-hidden="true">MATT VAPT KIT</div>

<section class="cover">
  <div class="ribbon">MATT VAPT KIT · INTERNAL REPOSITORY SCAN · NOT ISSUED BY CERT-PH</div>
  <div class="cover-night">
    <div class="cover-logo">{lockup_svg()}</div>
    <p class="kicker">Committed-code security scan</p>
    <h1>{esc(project)}</h1>
    <p class="cover-sub">Commit <span class="mono">{esc(summary["revision"][:12])}</span> · {len(summary["checks"])} check{"s" if len(summary["checks"]) != 1 else ""}</p>
  </div>
  <div class="cover-day">
    <dl class="cover-meta">
      <div><dt>Scanned</dt><dd>{esc(when)}</dd></div>
      <div><dt>Report ID</dt><dd>{esc(rid)}</dd></div>
      <div><dt>Classification</dt><dd class="tlp">TLP:{esc(tlp)}</dd></div>
    </dl>
    <p class="cover-note">An internal self-assessment of committed code, produced by Matt VAPT Kit {kit_version}.
    It is not a CERT-PH report, a penetration test or an all-clear. Findings are suspected until a person confirms them.</p>
  </div>
</section>

<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">01</p><h2>At a glance</h2></header>
  <p class="verdict">{esc(summary.get("recap") or "No plain-English summary was recorded for this scan.")}</p>
  <h3>What to do first</h3>
  <ol class="actions">{steps}</ol>
  <table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>{checks}</tbody></table>
  <p class="legend"><span class="chip review">Needs review</span> findings or a tool error to look at ·
  <span class="chip gap">Not run</span> a coverage gap, not a pass</p>
</section>

<section class="chapter page">
  <header class="chapter-head"><p class="eyebrow">02</p><h2>Secrets in the commit history</h2></header>
  {secrets}
</section>

<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">03</p><h2>Code-rule matches</h2></header>
  <p class="lede">Patterns in the committed code that often lead to vulnerabilities, grouped by rule.
  Source lines are deliberately not reproduced; open each location to judge it.</p>
  {static_html}
</section>

<section class="chapter page">
  <header class="chapter-head"><p class="eyebrow">04</p><h2>API routes without a login check</h2></header>
  <p class="lede">Handlers where no session or token check was found in the code. Middleware may still protect
  some of them, so confirm each one before treating it as a vulnerability.</p>
  {routes_html}
</section>

{staging_html}<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">{"06" if staging_html else "05"}</p><h2>Scope and limits</h2></header>
  <div class="scope">
    <div><h3>Covered by this scan</h3><ul>{covered or "<li>Nothing completed</li>"}</ul></div>
    <div><h3>Not covered</h3><ul>{not_tested}</ul></div>
  </div>
  <p class="closing">{esc(rid)} · Matt VAPT Kit {kit_version}. Committed code at
  {esc(summary["revision"][:12])}{" and read-only staging checks" if staging_html else ""}; working-tree changes,
  logged-in behaviour and business logic were not tested.
  Share this report only with people approved to see its findings.</p>
</section>
</body></html>"""


def write_scan_report(folder: Path, *, html_only: bool = False, tlp: str = "AMBER+STRICT") -> tuple[Path, Path | None]:
    """Write report.html (and report.pdf unless html_only or the PDF tools are missing) into the scan folder."""
    if tlp not in TLP_COLOR:
        raise ToolError("Unknown TLP classification.")
    document = render_scan(folder, tlp=tlp)
    html_path = folder / "report.html"
    write_private(html_path, document)
    if html_only:
        return html_path, None
    return html_path, print_pdf(document, folder / "report.pdf")


def pdf_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


def print_pdf(document: str, destination: Path) -> Path | None:
    """Print HTML to PDF with headless Chromium; None if the PDF tools aren't installed.

    The running header and footer come from the stylesheet's @page margin boxes, which can skip the cover.
    """
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
                pdf = page.pdf(format="A4", print_background=True, prefer_css_page_size=True, tagged=True, outline=True)
            finally:
                browser.close()
    except BrowserError:
        raise ToolError("Chromium could not print the PDF (it may be missing system libraries); "
                        "the HTML report was saved.") from None
    write_private(destination, pdf)
    return destination
