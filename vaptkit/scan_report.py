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
          "NOT RUN": ("gap", "Not run"), "CANCELLED": ("gap", "Cancelled"), "PARTIAL": ("gap", "Partial")}
LOCATION_LIMIT = 120
SCOPE_LABEL = {"runtime": "Runtime", "dev": "Dev only", "unused": "Unused dependency", "unknown": "Not classified"}
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
    messages = {}
    for path in files("vaptkit").joinpath("rules").iterdir():
        if path.name.endswith(".yml"):
            for rule in yaml.safe_load(path.read_text()).get("rules", []):
                messages[f"rules.{rule['id']}"] = rule["message"]
    return messages


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
        steps.append((f"Fix {route_count} API access-control finding{'s' if route_count != 1 else ''}.",
                      "Each handler either lacks a login check or changes a record chosen by a user ID from the request "
                      "without checking it belongs to the signed-in user. Section on API access control lists them."))
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
    def css_string(text: str) -> str:
        # This lands inside a CSS content: "..." value, not HTML - only quotes/backslashes/
        # newlines need escaping here, HTML entities would print literally in the PDF footer.
        return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")

    css = (files("vaptkit").joinpath("assets/scan-report.css").read_text()
           .replace("__TLP__", f"TLP:{tlp}")
           .replace("__FOOTER__", css_string(f"{project} · Repository scan · {when} · MVK v{kit_version}")))

    # Same rule as the route review: public routes and empty stub handlers are not findings.
    unauthenticated = [(route, handler) for route in routes.get("routes", []) for handler in route["handlers"]
                       if not handler["authentication"] and not handler.get("public") and not handler.get("stub")]
    findings = static.get("findings", [])
    steps = "".join(f"<li><div><strong>{esc(title)}</strong><span>{esc(detail)}</span></div></li>"
                    for title, detail in next_steps(summary, facts,
                                                    sum(item.get("runtime", True) for item in findings),
                                                    len(routes.get("findings", []))))
    checks = "".join(
        f'<tr><td class="check">{esc(stage(row))}</td><td class="state">{chip(row["status"])}</td>'
        f'<td>{esc(row["detail"])}</td></tr>' for row in summary["checks"])

    leaks = facts.get("leaks")
    history = next((row for row in summary["checks"] if stage(row) == "Secret history"), None)
    secret_rows = (read(folder, "secret-findings.json") or {}).get("findings", [])
    secret_table = ""
    if secret_rows:
        rows = "".join(
            f'<tr><td>{esc(item["rule"])}</td><td><code>{esc(item["file"])}:{esc(item["line"])}</code></td>'
            f'<td><code>{esc(item["commit"][:8])}</code></td><td><span class="chip {"gap" if item["placeholder"] else "review"}">'
            f'{"Likely placeholder" if item["placeholder"] else "Review"}</span></td></tr>' for item in secret_rows[:ROUTE_LIMIT])
        secret_table = ('<table><thead><tr><th>Rule</th><th>Where</th><th>Commit</th><th>Assessment</th></tr></thead>'
                        f'<tbody>{rows}</tbody></table><p class="more">Values are never stored. Placeholders are matches in '
                        'documentation or with example values; gitleaksignore-suggestions.txt has ignore lines for them.</p>')
    if leaks:
        secrets = (f'<p class="lede"><span class="count">{leaks}</span> possible secrets were found in the '
                   "commit history. The values are redacted and were never saved by the kit.</p>"
                   "<p>A secret stays exposed after it is deleted from the latest code, because every clone "
                   "still has the old commits. Treat each real one as leaked:</p><ul>"
                   "<li>Rotate or revoke it with the provider first.</li>"
                   "<li>Then decide whether the history needs rewriting.</li>"
                   "<li>Add reviewed false positives to <code>.gitleaksignore</code> so they stop reappearing.</li></ul>")
    elif history and history["status"] == "DONE" and facts.get("placeholders"):
        secrets = (f'<p class="lede">No likely real secrets. {facts["placeholders"]} matches look like placeholders in '
                   "documentation or example values.</p>")
    elif history and history["status"] == "DONE":
        secrets = '<p class="lede">No possible secrets were found in the commit history.</p>'
    else:
        secrets = ('<p class="lede">The secret-history check did not finish cleanly, so this part is not covered. '
                   "See the table in section 1 and run the scan again.</p>")

    messages = rule_messages()

    def rule_groups(items: list[dict]) -> str:
        grouped = {}
        for item in items:
            grouped.setdefault(item["rule"], []).append(item)
        sections = []
        for rule, matches in sorted(grouped.items(), key=lambda pair: -len(pair[1])):
            locations = "".join(f'<li>{esc(item["path"])}<span class="line">:{esc(item["line"])}</span></li>'
                                for item in matches[:LOCATION_LIMIT])
            more = (f'<p class="more">{len(matches) - LOCATION_LIMIT} more locations are listed in static-findings.json.</p>'
                    if len(matches) > LOCATION_LIMIT else "")
            sections.append(
                f'<div class="rule-group"><div class="rule-head"><h3>{esc(messages.get(rule, rule))}</h3>'
                f'<span class="count">{len(matches)}</span></div><p class="rule-id mono">{esc(rule)}</p>'
                f'<ul class="locations">{locations}</ul>{more}</div>')
        return "".join(sections)

    runtime_findings = [item for item in findings if item.get("runtime", True)]
    offline_findings = [item for item in findings if not item.get("runtime", True)]
    rule_sections = [rule_groups(runtime_findings)] if runtime_findings else []
    if offline_findings:
        rule_sections.append(
            f'<h3>Outside the running app ({len(offline_findings)})</h3><p class="muted">One-off scripts, migrations, '
            f'tests, docs and files nothing imports. They never run in the deployed app, so they are listed for '
            f'completeness only.</p>'
            + rule_groups(offline_findings))
    static_html = "".join(rule_sections) or '<p class="lede">No code-rule matches were recorded.</p>'
    if offline_findings and not runtime_findings:
        static_html = '<p class="lede">No matches in the running app.</p>' + static_html

    route_rows = "".join(
        f'<tr><td class="state"><span class="chip method">{esc(handler["method"])}</span></td>'
        f'<td><code>{esc(route["path"])}</code></td><td><code>{esc(route.get("file", ""))}</code></td></tr>'
        for route, handler in unauthenticated[:ROUTE_LIMIT])
    ownership = [item for item in routes.get("findings", []) if item["title"].startswith("Handler changes a record")]
    ownership_html = ""
    if ownership:
        rows = "".join(f'<tr><td><span class="chip method">{esc(item.get("method", "?"))}</span></td>'
                       f'<td><code>{esc(item["path"])}</code></td><td>{esc(item["impact"])}</td></tr>' for item in ownership)
        ownership_html = (f'<h3>Changes someone else\'s record ({len(ownership)})</h3><p>These handlers write using a user '
                          'ID taken from the request and never compare it with the signed-in user. Take the ID from the '
                          'session, or check ownership or role, before writing.</p>'
                          f'<table><thead><tr><th>Method</th><th>Route</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>')
    if unauthenticated:
        more = (f'<p class="more">{len(unauthenticated) - ROUTE_LIMIT} more are listed in route-review.json.</p>'
                if len(unauthenticated) > ROUTE_LIMIT else "")
        routes_html = ('<table><thead><tr><th>Method</th><th>Route</th><th>File</th></tr></thead>'
                       f"<tbody>{route_rows}</tbody></table>{more}")
    else:
        protected = routes.get("summary", {}).get("middleware_protected", 0)
        routes_html = ('<p class="lede">Every API handler that was reviewed requires a login'
                       + (f" ({protected} through the app's middleware rather than their own code)" if protected else "")
                       + ".</p>")
    routes_html = ownership_html + routes_html

    dependencies = read(folder, "dependency-audit.json")
    dependency_html = ""
    if dependencies is not None:
        band_chip = {"critical": "review", "high": "review", "medium": "gap", "low": "gap", "unknown": "gap"}

        def fix_cell(entry):
            fix = entry.get("fixed_version")
            return f"Upgrade to <strong>{esc(fix)}</strong> or later" if fix else "No fix published yet"

        def card(entry):
            severity_disagreement = (
                f'<dd>{esc(entry["severity_disagreement"])} <span class="muted">(per the advisory source)</span></dd>'
                if entry.get("severity_disagreement") else ""
            )
            return f"""<div class="finding-card">
  <div class="finding-card-head">
    <span class="finding-card-name">{esc(entry["package"])} <span class="muted">{esc(entry["version"])}</span></span>
    <span class="chip {band_chip[entry["severity"]]}">{esc(entry["severity"])}</span>
  </div>
  <dl class="finding-card-grid">
    <div><dt>Advisory</dt><dd><a href="https://osv.dev/vulnerability/{esc(entry["id"])}"><code>{esc(entry["id"])}</code></a></dd></div>
    <div><dt>Suggested fix</dt><dd>{fix_cell(entry)}</dd></div>
    <div><dt>Used in</dt><dd>{esc(SCOPE_LABEL.get(entry.get("scope"), "Runtime"))}</dd></div>
    {f'<div><dt>Disputed severity</dt>{severity_disagreement}</div>' if severity_disagreement else ""}
  </dl>
</div>"""

        cards = "".join(card(entry) for entry in dependencies["top"][:ROUTE_LIMIT])
        listed = ", ".join(f"<code>{esc(path)}</code>" for path in dependencies["lockfiles"])
        removable = [item for item in dependencies.get("unused_dependencies", []) if item["clears"]]
        removal = ("<p><strong>Quick win:</strong> nothing imports " + ", ".join(
            f'<code>{esc(item["name"])}</code> (clears {item["clears"]})' for item in removable)
                   + ". Removing them from package.json clears those high/critical findings.</p>") if removable else ""
        body = cards if cards else '<p class="lede">No known vulnerabilities in these lockfiles.</p>'
        dependency_html = f"""<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>Vulnerable dependencies</h2></header>
  <p class="lede">Known advisories for the exact package versions pinned in {listed}, from the public OSV
  database. "Dev only" packages (tests, build tools) don't ship, and "Unused dependency" ones come only through
  a dependency nothing in the code imports; fix runtime high and critical ones first. The suggested fix is the
  package's own published fixed version, not a guess.</p>
  {removal}
  {body}
  {'<p class="muted">Click an advisory ID above to open its official public database page (osv.dev) for the full '
    'technical write-up of that vulnerability.</p>' if cards else ""}
</section>
"""
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
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>Live staging checks</h2></header>
  <p class="lede">Read-only requests to <code>{esc(staging["target"])}</code>: security headers, cookies and a short list
  of commonly exposed files. No logins and no attack payloads. Confirmed means the same result was seen twice.</p>
  {table_html}{errors}
</section>
"""
    covered = "".join(f"<li>{esc(stage(row))}</li>" for row in summary["checks"]
                      if row["status"] in ("DONE", "REVIEW")
                      and not (not facts.get("staging_covered") and stage(row).startswith("Live staging")))

    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{esc(rid)} | {esc(project)} Repository Scan</title><style>{css}</style></head><body>
<div class="watermark" aria-hidden="true">MVK</div>

<section class="cover">
  <div class="ribbon">MVK · INTERNAL REPOSITORY SCAN · NOT ISSUED BY CERT-PH</div>
  <div class="cover-night">
    <div class="cover-logo">{lockup_svg()}</div>
    <p class="kicker">Committed-code security scan</p>
    <h1>{esc(project)}</h1>
    <p class="cover-sub">{f'Branch <span class="mono">{esc(summary["branch"])}</span> · ' if summary.get("branch") else ""}Commit <span class="mono">{esc(summary["revision"][:12])}</span> · {len(summary["checks"])} check{"s" if len(summary["checks"]) != 1 else ""}</p>
  </div>
  <div class="cover-day">
    <dl class="cover-meta">
      <div><dt>Scanned</dt><dd>{esc(when)}</dd></div>
      <div><dt>Report ID</dt><dd>{esc(rid)}</dd></div>
      <div><dt>Classification</dt><dd class="tlp">TLP:{esc(tlp)}</dd></div>
    </dl>
    <p class="cover-note">An internal self-assessment of committed code, produced by MVK {kit_version}.
    It is not a CERT-PH report, a penetration test or an all-clear. Findings are suspected until a person confirms them.</p>
  </div>
</section>

<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>At a glance</h2></header>
  <p class="verdict">{esc(summary.get("recap") or "No plain-English summary was recorded for this scan.")}</p>
  <h3>What to do first</h3>
  <ol class="actions">{steps}</ol>
  <table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>{checks}</tbody></table>
  <p class="legend"><span class="chip review">Needs review</span> findings or a tool error to look at ·
  <span class="chip gap">Not run</span> a coverage gap, not a pass</p>
</section>

<section class="chapter page">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>Secrets in the commit history</h2></header>
  {secrets}{secret_table}
</section>

{dependency_html}<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>Code-rule matches</h2></header>
  <p class="lede">Patterns in the committed code that often lead to vulnerabilities, grouped by rule.
  Source lines are deliberately not reproduced; open each location to judge it.</p>
  {static_html}
</section>

<section class="chapter page">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>API access control</h2></header>
  <p class="lede">Handlers where no session or token check was found in the code. Middleware may still protect
  some of them, so confirm each one before treating it as a vulnerability.</p>
  {routes_html}
</section>

{staging_html}<section class="chapter">
  <header class="chapter-head"><p class="eyebrow">§§</p><h2>Scope and limits</h2></header>
  <div class="scope">
    <div><h3>Covered by this scan</h3><ul>{covered or "<li>Nothing completed</li>"}</ul></div>
  </div>
  <p class="closing">{esc(rid)} · MVK {kit_version}. Committed code at
  {esc(summary["revision"][:12])}{" and read-only staging checks" if staging_html else ""}; working-tree changes,
  logged-in behaviour and business logic were not tested.
  Share this report only with people approved to see its findings.</p>
</section>
</body></html>"""
    # Number the chapters in order, since the dependency and staging chapters are optional.
    first, *chapters = document.split('<p class="eyebrow">§§</p>')
    return first + "".join(f'<p class="eyebrow">{number:02d}</p>{chapter}'
                           for number, chapter in enumerate(chapters, 1))


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
