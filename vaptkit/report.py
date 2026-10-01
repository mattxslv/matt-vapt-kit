import base64
import hashlib
import html
import json
import unicodedata
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from .assessment import create_output, load_json, write_private
from .process import ToolError

PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SEVERITY_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "informational": "Informational",
}
SEVERITY_COLOR = {
    "critical": "#7a1020", "high": "#b42318", "medium": "#b54708",
    "low": "#1d4f91", "informational": "#5b6b7c",
}
CVSS_RANGES = {
    "critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9),
    "low": (0.1, 3.9), "informational": (0.0, 0.0),
}
CHECK_LABELS = {
    "html_response": "HTML page response",
    "hsts_present": "HTTPS-only browser policy (HSTS)",
    "csp_present": "Browser script policy (CSP)",
    "nosniff": "Protection against guessing file types",
    "frame_policy_present": "Restrictions on embedding this page",
    "hsts_strong": "HSTS lasts at least 180 days",
    "csp_script_strong": "CSP blocks unsafe inline and eval scripts",
    "frame_policy_strong": "Embedding restricted to trusted origins",
    "referrer_policy_safe": "Referrer policy does not leak full URLs",
    "cookies_secure": "Cookies sent over HTTPS only (Secure)",
    "session_cookies_httponly": "Session cookies hidden from scripts (HttpOnly)",
    "no_version_disclosure": "Server software versions not disclosed",
}
OWASP = (
    ("A01", "Broken Access Control",
     "Users can act outside their intended permissions.",
     "Enforce access checks on the server for every request and deny by default."),
    ("A02", "Security Misconfiguration",
     "Insecure defaults, missing hardening or unnecessary exposed features.",
     "Use repeatable hardened configuration and review it regularly."),
    ("A03", "Software Supply Chain Failures",
     "Compromised or vulnerable dependencies, build systems or pipelines.",
     "Track components, monitor advisories and protect the build pipeline."),
    ("A04", "Cryptographic Failures",
     "Sensitive data is exposed through weak or missing cryptography.",
     "Use current protocols and algorithms and protect keys."),
    ("A05", "Injection",
     "Untrusted input reaches an interpreter such as SQL or a shell.",
     "Use parameterized APIs and validate input."),
    ("A06", "Insecure Design",
     "Missing or ineffective security controls in the design.",
     "Threat-model features and define security requirements early."),
    ("A07", "Authentication Failures",
     "Weak login, session or credential handling.",
     "Use strong session management, MFA and credential protection."),
    ("A08", "Software or Data Integrity Failures",
     "Code or data can be modified without verification.",
     "Verify signatures and protect update and data paths."),
    ("A09", "Security Logging and Alerting Failures",
     "Attacks are not detected or responded to in time.",
     "Log security events centrally and alert on them."),
    ("A10", "Mishandling of Exceptional Conditions",
     "Errors leave the system in an insecure state or leak information.",
     "Fail safely and avoid leaking details in errors."),
)
DEFAULT_OWASP = {"configuration": "A02", "unauthorized_access": "A01"}
TLP_LEVELS = ("RED", "AMBER+STRICT", "AMBER", "GREEN", "CLEAR")
TLP_COLOR = {
    "RED": "#c8102e", "AMBER+STRICT": "#b45309", "AMBER": "#b45309",
    "GREEN": "#15803d", "CLEAR": "#334155",
}
PROFILE_TYPES = {
    "unauthenticated-head-only": "Black-box self-assessment (unauthenticated, header-level)",
    "bearer-head-only": "Gray-box self-assessment (token gateway access, header-level)",
    "iap-browser-head-only": "Gray-box self-assessment (Google IAP sign-in, header-level)",
}
PHT = timezone(timedelta(hours=8))
FORMAT_ID = "MVK-SAR"


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def clean_label(value: str, field: str) -> str:
    value = (value or "").strip()
    if len(value) > 120 or any(unicodedata.category(char).startswith("C") for char in value):
        raise ToolError(f"{field} must be at most 120 printable characters.")
    return value


def validate_result(result: dict) -> None:
    schema = json.loads(files("vaptkit").joinpath("schemas/report.json").read_text())
    if next(Draft202012Validator(schema).iter_errors(result), None) is not None:
        raise ToolError("Report input does not match the assessment schema; contents withheld.")
    if result["status"] == "completed":
        paths = [item["path"] for item in result["observations"]]
        if (result["errors"] or not paths or paths != result["approved_paths"]
                or any(not 200 <= item["status"] < 300 for item in result["observations"])):
            raise ToolError("A completed report must contain a successful observation for every approved path and no errors.")
        if any(not 200 <= item["status"] < 300 for item in result.get("verification_observations", [])):
            raise ToolError("A completed report cannot contain a failed verification response.")
    if result["profile"] in PROFILE_TYPES and (
        result["coverage"]["data_exposure"] != "not_tested"
        or result["coverage"]["unauthorized_access"] != "not_tested"
    ):
        raise ToolError("HEAD-only profiles cannot claim data-exposure or access-control test coverage.")
    for finding in result["findings"]:
        cvss = finding.get("cvss")
        if cvss is None:
            continue
        low, high = CVSS_RANGES[finding["severity"]]
        if round(cvss["score"], 1) != cvss["score"] or not low <= cvss["score"] <= high:
            raise ToolError("CVSS score must have one decimal place and match the finding severity.")
        if not cvss["vector"].startswith(f"CVSS:{cvss['version']}/"):
            raise ToolError("CVSS vector must match its declared version.")


def conclusion(result: dict, category: str) -> str:
    findings = [finding for finding in result["findings"] if finding["category"] == category]
    if any(finding["verification"] == "confirmed" for finding in findings):
        return "Confirmed"
    if findings:
        return "Suspected"
    if result["status"] == "incomplete" or result["coverage"][category] == "not_tested":
        return "Not tested"
    return "Not observed in tested scope"


def timestamp(value: str):
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(PHT) if moment.tzinfo else None


def long_date(value: str) -> str:
    moment = timestamp(value)
    return f"{moment.day} {moment:%B %Y}" if moment else esc(value)


def long_time(value: str) -> str:
    moment = timestamp(value)
    return f"{moment.day} {moment:%B %Y, %H:%M} PHT" if moment else esc(value)


def report_id(result: dict) -> str:
    moment = timestamp(result["started_at"])
    day = f"{moment:%Y%m%d}" if moment else "UNDATED"
    return f"MVK-{result['project'].upper()}-{day}-{result['scope_sha256'][:6].upper()}"


def owasp_code(finding: dict):
    return finding.get("owasp") or DEFAULT_OWASP.get(finding["category"])


def severity_text(finding: dict) -> str:
    label = SEVERITY_LABEL[finding["severity"]]
    cvss = finding.get("cvss")
    return f"{label} ({cvss['score']:.1f})" if cvss else f"{label} (not scored)"


def severity_chart(findings: list[dict]) -> str:
    counts = {severity: 0 for severity in SEVERITY_LABEL}
    for finding in findings:
        counts[finding["severity"]] += 1
    total = sum(counts.values())
    rows = []
    for row, (severity, label) in enumerate(SEVERITY_LABEL.items()):
        width = round(300 * counts[severity] / total) if total else 0
        y = row * 30
        rows.append(
            f'<text x="0" y="{y + 18}" class="chart-label">{label}</text>'
            f'<rect x="130" y="{y + 5}" width="300" height="18" fill="#eef2f7"/>'
            f'<rect x="130" y="{y + 5}" width="{width}" height="18" fill="{SEVERITY_COLOR[severity]}"/>'
            f'<text x="{440}" y="{y + 18}" class="chart-value">{counts[severity]}</text>'
        )
    return (
        '<svg class="chart" role="img" aria-label="Findings by severity" viewBox="0 0 480 152">'
        + "".join(rows) + "</svg>"
    )


def check_cell(observation: dict, key: str) -> str:
    if not 200 <= observation["status"] < 300:
        return "Not assessed (non-2xx response)"
    return "Observed" if observation["checks"][key] else "Not observed"


def render(result: dict, screenshots=(), *, tlp="AMBER+STRICT", prepared_by="", agency="") -> str:
    validate_result(result)
    if tlp not in TLP_LEVELS:
        raise ToolError("Unsupported TLP level.")
    prepared_by = clean_label(prepared_by, "Prepared by")
    agency = clean_label(agency, "Agency/Office")
    css = files("vaptkit").joinpath("assets/report.css").read_text()
    kit_version = version("matt-vapt-kit")
    rid = report_id(result)
    project = result["project"].upper()
    findings = sorted(result["findings"], key=lambda item: PRIORITY[item["severity"]])
    observations = result["observations"]
    images = {index: (data, sha) for index, data, sha in screenshots}
    figure_for_path = {item["path"]: index for index, item in enumerate(observations, 1)}
    incomplete = result["status"] == "incomplete"
    fixture = result["status"] == "fixture"
    exposure = conclusion(result, "data_exposure")
    access = conclusion(result, "unauthorized_access")
    assessment_type = PROFILE_TYPES.get(result["profile"], result["profile"])

    banner = ""
    if fixture:
        banner = '<div class="state-banner"><strong>SYNTHETIC EXAMPLE.</strong> This is not a live assessment.</div>'
    elif incomplete:
        banner = ('<div class="state-banner"><strong>INCOMPLETE ASSESSMENT.</strong> '
                  'Some approved checks did not run. See Section 2.</div>')

    if incomplete:
        synopsis_result = ("Assessment incomplete. Resolve the access or execution issue in Section 2 "
                           "before drawing conclusions about the application.")
    elif findings:
        synopsis_result = (f"The assessment recorded {len(findings)} finding(s). "
                           "They are listed in Section 2 and detailed in Section 4.2.")
    else:
        synopsis_result = ("No findings were recorded within the tested scope. "
                           "This is not an all-clear; untested areas are listed in Section 2.")

    finding_rows = "".join(
        f"<tr><td>{esc(item['title'])}</td>"
        f'<td><span class="sev sev-{item["severity"]}">{esc(severity_text(item))}</span></td>'
        f"<td>{esc(item['verification'].capitalize())}</td></tr>"
        for item in findings
    ) or '<tr><td colspan="3">No findings recorded within the tested scope.</td></tr>'

    owasp_counts = {code: 0 for code, *_ in OWASP}
    unmapped = 0
    for item in findings:
        code = owasp_code(item)
        if code in owasp_counts:
            owasp_counts[code] += 1
        else:
            unmapped += 1
    owasp_rows = "".join(
        f"<tr><td>{code}: {esc(name)}</td><td class=\"num\">{owasp_counts[code]}</td></tr>"
        for code, name, *_ in OWASP
    )
    if unmapped:
        owasp_rows += f'<tr><td>Not mapped to a category</td><td class="num">{unmapped}</td></tr>'

    errors = "".join(
        f"<tr><td><code>{esc(error['path'])}</code></td><td>{esc(error['kind'].capitalize())}</td>"
        f"<td>{esc(error['message'])}</td></tr>"
        for error in result["errors"]
    )
    stopped = (
        '<h3>Stopped or failed checks</h3><table><thead><tr><th>Path</th><th>Type</th>'
        f"<th>Detail</th></tr></thead><tbody>{errors}</tbody></table>"
    ) if errors else ""

    recommendations = []
    for item in findings:
        if item["remediation"] not in recommendations:
            recommendations.append(item["remediation"])
    if incomplete:
        recommendations.append("Resolve the stopped checks in Section 2 and rerun the assessment before drawing conclusions.")
    if result["coverage"]["unauthorized_access"] == "not_tested":
        recommendations.append(
            "Perform authenticated role, ownership and workflow testing (OWASP A01) before submitting the "
            "system for external VAPT. Confirm that every API enforces access checks on the server."
        )
    if result["coverage"]["data_exposure"] == "not_tested":
        recommendations.append(
            "Review API responses, client bundles and diagnostic endpoints for sensitive data. "
            "This profile did not inspect response bodies."
        )
    recommendations.append("Retest every remediated finding and record the result.")
    recommendation_items = "".join(f"<li>{esc(text)}</li>" for text in recommendations)

    observation_rows = "".join(
        f"<tr><td><code>{esc(item['method'])} {esc(item['path'])}</code></td>"
        f"<td class=\"num\">{item['status']}</td>"
        + "".join(f"<td>{esc(check_cell(item, key))}</td>" for key in
                  ("hsts_present", "csp_present", "nosniff", "frame_policy_present"))
        + "</tr>"
        for item in observations
    ) or '<tr><td colspan="6">No HTTP observations were captured.</td></tr>'
    commands = "".join(
        f"<li><code>{esc(item['method'])} {esc(result['target'].rstrip('/'))}{esc(item['path'])}</code>"
        f" (HTTP {item['status']})</li>"
        for item in result.get("requests", observations)
    )
    figures = []
    for index, item in enumerate(observations, 1):
        if index in images:
            data, sha = images[index]
            figures.append(
                f'<figure><img alt="Rendered observation for {esc(item["path"])}" src="data:image/png;base64,{data}">'
                f"<figcaption>Figure 4.1.{index}: Rendered HEAD response observation for "
                f"<code>{esc(item['path'])}</code> (Matt VAPT Kit evidence, not a capture of the live page). "
                f"SHA-256: <code>{sha}</code></figcaption></figure>"
            )
        else:
            figures.append(
                f'<p class="muted">Figure 4.1.{index}: see evidence record E{index:02d} in Appendix D.</p>'
            )

    vulnerability_blocks = []
    for severity, label in SEVERITY_LABEL.items():
        group = [item for item in findings if item["severity"] == severity]
        if not group:
            continue
        blocks = []
        for item in group:
            figure = figure_for_path.get(item["path"])
            evidence = f"<p><strong>Evidence:</strong> Figure 4.1.{figure}.</p>" if figure else ""
            cvss = item.get("cvss")
            score = (f"<p><strong>CVSS {esc(cvss['version'])}:</strong> {cvss['score']:.1f} "
                     f"<code>{esc(cvss['vector'])}</code></p>") if cvss else ""
            code = owasp_code(item)
            owasp_name = next((name for c, name, *_ in OWASP if c == code), None)
            owasp_line = f"<p><strong>OWASP Top 10 (2025):</strong> {code}: {esc(owasp_name)}</p>" if owasp_name else ""
            blocks.append(
                f'<article class="finding"><h4>{esc(item["title"])}</h4>'
                f"<p>{esc(item['impact'])}</p>{evidence}"
                f"<p><strong>Verification:</strong> {esc(item['verification'].capitalize())}"
                + (f" ({esc(item['evidence'])})" if item.get("evidence") else "") + f"</p>{score}{owasp_line}"
                f"<p><strong>Solution:</strong></p><p>{esc(item['remediation'])}</p>"
                f"<p><strong>Affected Links/Assets:</strong></p><ul><li><code>"
                f"{esc(result['target'].rstrip('/'))}{esc(item['path'])}</code></li></ul></article>"
            )
        vulnerability_blocks.append(f'<h3 class="sev-heading sev-{severity}">{label.upper()}</h3>' + "".join(blocks))
    exposure_labels = {
        "baseline": "Random path baseline", "secret_file": "Environment file", "vcs": "Git metadata",
        "debug": "Debug endpoint", "health": "Health endpoint", "api_docs": "API documentation",
        "source_map": "JavaScript source map",
    }
    exposure_rows = "".join(
        f"<tr><td><code>{esc(item['path'])}</code></td><td>{esc(exposure_labels[item['kind']])}</td>"
        f"<td class=\"num\">{item['status']}</td><td>"
        + ("Baseline" if item["kind"] == "baseline" else
           "Exposed (signature matched)" if item["exposed"] and item["signature"] else
           "Possibly exposed" if item["exposed"] else "No exposure confirmed")
        + "</td></tr>"
        for item in result.get("exposure", [])
    )
    exposure_html = (
        "<p>A fixed list of commonly leaked paths was checked. A random path was requested first so that "
        "catch-all pages can be filtered out. Content signatures used at most the first 2 KB, which was not stored. "
        "Public documentation and diagnostic metadata require owner review before treating them as vulnerabilities. "
        "No matching signature does not prove that a resource is safe.</p>"
        "<table><thead><tr><th>Path</th><th>Check</th><th>Status</th><th>Result</th></tr></thead>"
        f"<tbody>{exposure_rows}</tbody></table><p class=\"caption\">Table 4.2: Public exposure checks</p>"
    ) if exposure_rows else '<p class="muted">Not performed in this profile.</p>'
    retest_labels = {"still_present": "Still present", "resolved": "Resolved", "not_rechecked": "Not rechecked"}
    retest_html = (
        "<h3>4.4 Retest Results</h3><p>Comparison with the previous assessment. "
        "Not rechecked means equivalent evidence was unavailable or inconclusive.</p>"
        "<table><thead><tr><th>Finding</th><th>Path</th><th>Result</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td>{esc(item['title'])}</td><td><code>{esc(item['path'])}</code></td>"
            f"<td>{esc(retest_labels[item['status']])}</td></tr>"
            for item in result["retest"]
        ) + '</tbody></table><p class="caption">Table 4.3: Retest of previous findings</p>'
    ) if result.get("retest") else ""
    vulnerabilities = "".join(vulnerability_blocks) or (
        "<p>No vulnerabilities were identified within the tested scope. "
        "Untested areas are listed in Section 2.</p>"
    )

    cleanup = (("This profile sent HTTP HEAD and bounded GET requests. " if result["profile"] == "unauthenticated-exposure"
                else "This profile sent only HTTP HEAD requests. ") + "No accounts, files, records or "
               "configuration were created or modified on the target.")
    if result["profile"] == "iap-browser-head-only":
        cleanup += (" Google IAP sign-in state may remain in the operator's private toolkit browser "
                    "profile on the assessment workstation. It is not part of this report.")
    elif result["profile"] == "bearer-head-only":
        cleanup += " The access token was supplied through an environment variable and was not written to any artifact."

    evidence_records = []
    for index, item in enumerate(observations, 1):
        rows = "".join(
            f"<tr><td>{esc(CHECK_LABELS[key])}</td><td>{esc(check_cell(item, key) if key != 'html_response' else ('Yes' if value else 'No'))}</td></tr>"
            for key, value in item["checks"].items()
        )
        evidence_records.append(
            f'<article class="evidence" id="evidence-{index}">'
            f'<div class="evidence-label">MATT VAPT KIT | RENDERED HTTP OBSERVATION | E{index:02d}</div>'
            f"<h4>{esc(item['method'])} {esc(item['path'])}</h4>"
            f"<p>HTTP status: <strong>{item['status']}</strong></p>"
            f"<table><thead><tr><th>Check</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>"
            "<p class=\"muted\">Response bodies, cookies and raw header values were not retained. "
            "Header values were graded at capture time against fixed rules; only the pass or fail results were kept.</p></article>"
        )
    evidence_html = "".join(evidence_records) or "<p>No HTTP observations were captured.</p>"

    severity_appendix = "".join(
        f'<tr><td class="nowrap"><span class="sev sev-{severity}">{label}</span></td><td class="nowrap">{CVSS_RANGES[severity][0]:.1f}'
        f"{'' if severity == 'informational' else f' to {CVSS_RANGES[severity][1]:.1f}'}</td><td>{esc(text)}</td></tr>"
        for (severity, label), text in zip(SEVERITY_LABEL.items(), (
            "Fix immediately. Exploitation is straightforward and can fully compromise the system or its data.",
            "Fix as a priority. Exploitation is practical and seriously affects confidentiality, integrity or availability.",
            "Fix in the normal release cycle. Exploitation needs more skill or conditions, or has limited impact.",
            "Fix when practical. Typically limited information disclosure without direct compromise.",
            "No direct risk. Recorded for awareness or hardening.",
        ))
    )
    owasp_appendix = "".join(
        f"<tr><td>{code}: {esc(name)}</td><td>{esc(description)}</td><td>{esc(prevention)}</td></tr>"
        for code, name, description, prevention in OWASP
    )
    tlp_rows = "".join(
        f'<tr><td><span class="tlp" style="color:{TLP_COLOR[level]}">TLP:{level}</span></td><td>{esc(text)}</td></tr>'
        for level, text in (
            ("RED", "Named recipients only. No further sharing."),
            ("AMBER+STRICT", "Recipients' own organization only, on a need-to-know basis."),
            ("AMBER", "Recipients' organization and its clients, on a need-to-know basis."),
            ("GREEN", "The wider community, but not public channels."),
            ("CLEAR", "No restriction on disclosure."),
        )
    )

    toc = "".join(
        f'<li><a href="#{anchor}">{esc(title)}</a></li>'
        for anchor, title in (
            ("s1", "1 Executive Summary"), ("s2", "2 Key Findings"), ("s3", "3 Recommendation"),
            ("s4", "4 Vulnerability Findings"), ("s5", "5 Clean-up"), ("s6", "6 Disclaimer"),
            ("aa", "Appendix A: Severity Classification"), ("ab", "Appendix B: OWASP Top 10 (2025)"),
            ("ac", "Appendix C: Traffic Light Protocol"), ("ad", "Appendix D: Evidence Record"),
        )
    )
    prepared_line = esc(prepared_by) if prepared_by else "&nbsp;"
    agency_text = esc(agency) if agency else "Not specified"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{esc(rid)} | {esc(project)} Self-Assessment Report</title><style>{css}</style></head><body>
<div class="watermark" aria-hidden="true">MATT VAPT KIT | SELF-ASSESSMENT</div>
<main>
<section class="cover">
  <div class="mvk-ribbon">MATT VAPT KIT | INTERNAL SELF-ASSESSMENT | NOT ISSUED BY CERT-PH</div>
  <div class="cover-mark"><span class="mvk-badge">MVK</span><span>Matt VAPT Kit</span></div>
  <p class="cover-kicker">PENETRATION TESTING REPORT</p>
  <h1>{esc(project)}<span>Self-Assessment</span></h1>
  <p class="cover-target">{esc(result['target'])}</p>
  {banner}
  <dl class="cover-meta">
    <div><dt>Date of Report</dt><dd>{long_date(result['finished_at'])}</dd></div>
    <div><dt>Report ID</dt><dd>{esc(rid)}</dd></div>
    <div><dt>Classification</dt><dd><span class="tlp" style="color:{TLP_COLOR[tlp]}">TLP:{esc(tlp)}</span></dd></div>
  </dl>
  <p class="cover-note">This is not a CERT-PH report or certification. It was produced by the
  Matt VAPT Kit for internal review before external assessment.</p>
</section>

<section class="info-page">
  <h2 class="doc-title">SELF-ASSESSMENT REPORT</h2>
  <table class="info-table"><tbody>
    <tr><th>Report ID</th><td>{esc(rid)}</td></tr>
    <tr><th>Agency/Office</th><td>{agency_text}</td></tr>
    <tr><th>System</th><td>{esc(project)}</td></tr>
    <tr><th>Prepared by</th><td>{prepared_line if prepared_by else 'Matt VAPT Kit (automated)'}</td></tr>
    <tr><th>Type of Assessment</th><td>{esc(assessment_type)}</td></tr>
    <tr><th>Start</th><td>{long_time(result['started_at'])}</td></tr>
    <tr><th>End</th><td>{long_time(result['finished_at'])}</td></tr>
    <tr><th>Format</th><td>{FORMAT_ID} v{esc(kit_version)}</td></tr>
  </tbody></table>
  <div class="signoff">
    <div><span class="line">{prepared_line}</span><span>PREPARED BY</span></div>
    <div><span class="line">&nbsp;</span><span>REVIEWED BY</span></div>
  </div>
  <h2 class="toc-title">TABLE OF CONTENTS</h2>
  <ol class="toc">{toc}</ol>
</section>

<section id="s1" class="chapter">
  <h2>1 EXECUTIVE SUMMARY</h2>
  <h3>1.1 Synopsis</h3>
  <p>The Matt VAPT Kit performed an internal security self-assessment of the {esc(project)}
  staging environment at <code>{esc(result['target'])}</code> between {long_time(result['started_at'])}
  and {long_time(result['finished_at'])}. The assessment type was: {esc(assessment_type)}.</p>
  <p>{esc(synopsis_result)}</p>
  <p>The purpose of this self-assessment is to find and fix weaknesses before an external
  vulnerability assessment and penetration test. It does not replace one.</p>
  <h3>1.2 Scope</h3>
  <h4>Web Application Information</h4>
  <table><thead><tr><th>Asset</th><th>Type</th><th>URL</th></tr></thead><tbody>
    <tr><td class="nowrap">{esc(project)}</td><td>Web Application - Staging Environment</td><td><code>{esc(result['target'])}</code></td></tr>
  </tbody></table>
  <p class="caption">Table 1.1: Target asset for the self-assessment</p>
  <h4>Testing Methodologies</h4>
  <table><thead><tr><th>Methods/Techniques</th><th>Status</th></tr></thead><tbody>
    <tr><td>HTTP response header inspection (HEAD requests)</td><td>Performed</td></tr>
    <tr><td>Reconnaissance and directory discovery</td><td>Not performed</td></tr>
    <tr><td>Privilege escalation / lateral movement</td><td>Not performed</td></tr>
    <tr><td>Denial of service checks</td><td>Not performed</td></tr>
    <tr><td>Viewing/using sensitive data for further checking</td><td>Not performed</td></tr>
  </tbody></table>
  <p class="caption">Table 1.2: Methodologies used during the self-assessment</p>
</section>

<section id="s2" class="chapter">
  <h2>2 KEY FINDINGS</h2>
  <h3>{esc(project)} Findings Overview</h3>
  <table><thead><tr><th>Findings</th><th>Severity</th><th>Verification</th></tr></thead>
  <tbody>{finding_rows}</tbody></table>
  <p class="caption">Table 2.1: List of findings</p>
  <h3>Overall Vulnerability Findings</h3>
  {severity_chart(findings)}
  <p class="caption">Figure 2.1: Findings by severity</p>
  <h3>Coverage</h3>
  <table><thead><tr><th>Question</th><th>Result</th></tr></thead><tbody>
    <tr><td>Was data exposure found?</td><td><strong>{exposure}</strong></td></tr>
    <tr><td>Was unauthorized access found?</td><td><strong>{access}</strong></td></tr>
  </tbody></table>
  <p class="caption">Table 2.2: Coverage of the two primary risk questions</p>
  <p>{esc(result['coverage']['note'])}</p>
  <p class="muted">A clean result cannot establish that no historical data leak occurred.
  Redirects are not followed. Non-2xx responses are coverage gaps, not passing checks.</p>
  {stopped}
  <h3>OWASP Top 10 (2025) Mapping</h3>
  <table><thead><tr><th>OWASP Top 10 (2025)</th><th>Vulnerability Count</th></tr></thead>
  <tbody>{owasp_rows}</tbody></table>
  <p class="caption">Table 2.3: Findings mapped to the OWASP Top 10 (2025) categories</p>
</section>

<section id="s3" class="chapter">
  <h2>3 RECOMMENDATION</h2>
  <p>Prioritize higher-severity findings, but fix every finding recorded in this report.</p>
  <ul>{recommendation_items}</ul>
</section>

<section id="s4" class="chapter">
  <h2>4 VULNERABILITY FINDINGS</h2>
  <h3>4.1 Reconnaissance and Information Gathering</h3>
  <h4>External Footprinting</h4>
  <p class="muted">Not performed in this profile.</p>
  <h4>HTTP Response Header Inspection</h4>
  <p>The kit graded approved HEAD responses against fixed rules. Findings marked Confirmed were
  reproduced on a second request. Stopped checks and unverified findings are identified separately.</p>
  <table><thead><tr><th>Request</th><th>Status</th><th>HSTS</th><th>CSP</th><th>nosniff</th><th>Frame policy</th></tr></thead>
  <tbody>{observation_rows}</tbody></table>
  <p class="caption">Table 4.1: HTTP response header observations</p>
  {''.join(figures)}
  <p><strong>Commands:</strong></p><ul class="commands">{commands}</ul>
  <h4>Public Exposure Checks</h4>
  {exposure_html}
  <h4>Service Enumeration and Fingerprinting</h4>
  <p class="muted">Not performed in this profile.</p>
  <h3>4.2 Vulnerability Identification</h3>
  {vulnerabilities}
  <h3>4.3 Attack and Exploitation</h3>
  <p>No exploitation was attempted. This profile is non-intrusive.</p>
  {retest_html}
</section>

<section id="s5" class="chapter">
  <h2>5 CLEAN-UP</h2>
  <p>{esc(cleanup)}</p>
</section>

<section id="s6" class="chapter">
  <h2>6 DISCLAIMER</h2>
  <p>This report is an internal self-assessment generated by the Matt VAPT Kit. It is not
  issued by CERT-PH or the DICT Cybersecurity Bureau and is not a certification of security.
  Results apply only to the target, time window and checks listed above. Automated observations
  require human review before action. The system owner remains responsible for remediation.</p>
</section>

<section id="aa" class="chapter">
  <h2>APPENDIX A</h2><h3>Severity Classification</h3>
  <table><thead><tr><th>Level</th><th>CVSS v3.1</th><th>Description</th></tr></thead>
  <tbody>{severity_appendix}</tbody></table>
  <p class="muted">Scores are shown only when a finding has a justified CVSS vector. Unscored findings
  use the severity assigned by the assessor.</p>
</section>

<section id="ab" class="chapter">
  <h2>APPENDIX B</h2><h3>OWASP Top 10 (2025)</h3>
  <table><thead><tr><th>Category</th><th>Description</th><th>Prevention</th></tr></thead>
  <tbody>{owasp_appendix}</tbody></table>
</section>

<section id="ac" class="chapter">
  <h2>APPENDIX C</h2><h3>Traffic Light Protocol</h3>
  <p>This report is marked <span class="tlp" style="color:{TLP_COLOR[tlp]}">TLP:{esc(tlp)}</span>.</p>
  <table><thead><tr><th>Label</th><th>Sharing</th></tr></thead><tbody>{tlp_rows}</tbody></table>
</section>

<section id="ad" class="chapter">
  <h2>APPENDIX D</h2><h3>Evidence Record</h3>
  <p>Scope fingerprint: <code>{esc(result['scope_sha256'])}</code></p>
  {evidence_html}
</section>

<footer class="screen-footer">{FORMAT_ID} v{esc(kit_version)} | {esc(rid)} | Matt VAPT Kit internal
self-assessment, not a CERT-PH report | TLP:{esc(tlp)}</footer>
</main></body></html>"""


def merge_source_review(result: dict, review: dict) -> dict:
    """Add suspected findings from `vapt review-routes` for the same project."""
    if not isinstance(review, dict) or review.get("kind") != "route-review" or review.get("project") != result.get("project"):
        raise ToolError("Source review must be a route review for the same project.")
    findings = review.get("findings", [])
    if len(result["findings"]) + len(findings) > 100:
        raise ToolError("Too many findings for one report; fix or scope the route review first.")
    merged = dict(result, findings=result["findings"] + findings, coverage=dict(result["coverage"]))
    summary = review.get("summary", {})
    merged["coverage"]["note"] = (
        f"{result['coverage']['note']} Static source review of revision {str(review.get('revision', ''))[:12]} "
        f"covered {summary.get('handlers', 0)} API handlers; its findings are suspected until confirmed live."
    )[:2000]
    return merged


def generate(source: Path, output: Path, *, reviewed: bool, html_only=False,
             tlp="AMBER+STRICT", prepared_by="", agency="", source_review: Path | None = None) -> Path:
    if not reviewed:
        raise ToolError("Review and redact the JSON first, then pass --reviewed. Automatic redaction cannot guarantee safety.")
    result = load_json(source)
    if source_review is not None:
        validate_result(result)
        result = merge_source_review(result, load_json(source_review, limit=5_000_000))
    options = {"tlp": tlp, "prepared_by": prepared_by, "agency": agency}
    document = render(result, **options)
    if not html_only:
        try:
            from playwright.sync_api import Error as BrowserError, sync_playwright
        except ImportError:
            raise ToolError("Install matt-vapt-kit[report] and Playwright Chromium, or use --html-only.") from None
    create_output(output)
    if not html_only:
        rid = esc(report_id(result))
        kit_version = esc(version("matt-vapt-kit"))
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
                    document = render(result, images, **options)
                    page.set_content(document, wait_until="load")
                    pdf = page.pdf(
                        format="A4", print_background=True, prefer_css_page_size=True,
                        tagged=True, outline=True, display_header_footer=True,
                        header_template=(
                            '<div style="font-size:8px;width:100%;padding:0 18mm;color:#3b4a5c;'
                            'display:flex;justify-content:space-between">'
                            '<span>Penetration Testing Report | Self-Assessment</span>'
                            f'<span style="font-weight:700;color:{TLP_COLOR[tlp]}">TLP:{esc(tlp)}</span></div>'
                        ),
                        footer_template=(
                            '<div style="font-size:7.5px;width:100%;padding:0 18mm;color:#526374;'
                            'display:flex;justify-content:space-between">'
                            f'<span>{FORMAT_ID} v{kit_version} | {rid} | Matt VAPT Kit self-assessment, not a CERT-PH report</span>'
                            '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
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
