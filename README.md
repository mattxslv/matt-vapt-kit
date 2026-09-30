# Matt VAPT Kit

Private security self-assessment tooling for team-owned systems.
This is an internal assessment, not a CERT-PH report or certification.

## What works today

- A non-root Docker runner with curl, DNS utilities, ffuf, Git, Nmap and WhatWeb.
- Digest-pinned, separate Docker services for ZAP, Nuclei, Gitleaks, Semgrep,
  Subfinder and testssl.sh. They do not run automatically.
- Offline validation of staging-only YAML configuration with exact host allowlists.
- PEMEDES configuration and a DTAP draft. No application repositories modified.

No scanning, hooks, scheduled workflows, screenshot capture or report generation
is implemented yet. `vapt validate` checks configuration, not website security.
Container services default to **no network access**. This foundation intentionally
cannot authorize a scan.

## Start locally

```sh
docker compose build kit
docker compose run --rm kit doctor
docker compose run --rm kit validate projects/pemedes.vapt.yml
docker compose run --rm kit validate projects/dtap.vapt.yml
```

These commands do not contact the target websites. Docker build downloads packages
from their publishers. The core base and auxiliary images are pinned by digest;
Debian packages resolve from the distribution repositories at build time, so the
build is not fully reproducible. Update and revalidate tool pins regularly.

For local development:

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

`vapt doctor` returns nonzero if a core executable is missing. It checks availability,
not scanner effectiveness. Use the Docker runner for consistent tool availability.

## Project configuration

Start with `projects/pemedes.vapt.yml`. Eventually each application repository will
hold its own `.vapt.yml`. The schema is `vaptkit/schemas/project.json`.

- Only an exact HTTPS origin on port 443 is accepted. No wildcards or embedded credentials.
- `environment: staging` is a declaration, not proof the server is a test environment.
- A reachable server is not permission to scan. A separate approved scope is required.
- Roles must be confirmed before authenticated checks. DTAP's roles are intentionally
  empty until reviewed, and its URL did not respond during setup.
- Credentials are environment-variable **names**, never values:

```yaml
credentials:
  admin:
    token_env: VAPT_PEMEDES_ADMIN_TOKEN
```

The foundation does not load credentials. Future adapters must enforce path scope,
redirect limits and rate limits themselves; a config file alone is not enforcement.
PEMEDES's export exclusion is only a starting point, not a complete safe scan scope.

## Safety and evidence

Before any active assessment, record the authorized owner, exact hostnames, test
window, allowed techniques, rate/concurrency limits, test accounts, exclusions,
stop conditions and cleanup procedure. Do not scan shared cloud IP ranges.
Do not assume a production WAF or IAM configuration matches staging.

ZAP baseline uses passive detection but its crawler still sends requests. Even GET
requests can log users out or trigger poorly designed actions. No automatic crawling,
directory discovery, Nuclei template execution, port scans or production checks
will be enabled without approved scope. Broad vulnerability scripts are not a default.
Use synthetic test data, disable real email/payment side effects and avoid destructive
or availability tests.

Keep code, credentials, reports and customer data off third-party scanning services.
Subfinder is included as a dormant tool; its external providers are not enabled.
TheHarvester and external search-provider reconnaissance are deferred until data
sharing and scope are approved. Wordlists will be selected and pinned with adapters
rather than installing a large, unbounded discovery list.

Reports and screenshots belong in restricted storage, not Git or public issues.
The ignore file is a guardrail, not access control. Redact tokens, cookies, personal
data and secret values before screenshots are persisted or shared. Capture only the
minimum evidence. Raw API/terminal output rendered as an image must be labeled as
rendered evidence, not passed off as an original browser screenshot.

## Planned report

Title: **Matt VAPT Kit | Internal Self-Assessment**. Use an original layout, not
CERT-PH branding, signatures or report numbers.

The summary answers "Was data exposure found?" and "Was unauthorized access found?"
using **Confirmed**, **Suspected**, **Not observed in tested scope**, or **Not tested**.
A clean scan cannot establish that no leak occurred. Proving a historical breach
requires incident investigation, not just a vulnerability scan.

Every finding includes plain-language impact, affected scope, evidence provenance,
redacted screenshots when useful, verification status, remediation and retest result.
Include CVSS version/vector only when justified. Do not invent scores or treat an
automated alert as confirmed. Show untested roles, blocked routes and tool errors.
Screenshots supplement searchable text, they do not replace it.

Public JavaScript and API route names are normal web application behavior, not
automatically source disclosure vulnerabilities. `NEXT_PUBLIC_*` variable names alone
do not establish a bypass. Confirm actual values, server-side enforcement and impact.
A minimal public liveness endpoint can be appropriate; internal diagnostics need
separate access controls. No PEMEDES findings have been validated by this toolkit.

## Rollout and cadence

| Stage | Delivery |
|---|---|
| Foundation (current) | Docker runner, tool inventory, config validation |
| Push checks | Local pre-push checks plus Actions on main/staging pushes, no PR required |
| Assessment runner | Scoped staging adapters and manual role/ownership/workflow checks |
| Reporting | Original HTML/PDF, plain-language findings, redacted screenshots |
| Scheduling | Weekly staging baseline, private findings tracking |
| Expansion | DWAD Hub, ERMC and Gateway API after PEMEDES and DTAP |

Push checks will include secret scanning and dependency checks locally, with CodeQL
and Semgrep in CI where repository licensing permits. Check CodeQL eligibility for
private repositories before enabling it. Local hooks are bypassable, so CI remains
necessary. Use local Semgrep rules without telemetry or source uploads.

Cloud Build may deploy concurrently with a push-triggered GitHub Action. Advisory
checks **do not block deployment or necessarily run after it**. No deployment wiring
will change without explicit approval. A future release gate must be connected to
the actual Cloud Build pipeline if required.

Run automated checks on every push, vulnerability advisory monitoring daily, a scoped
staging baseline weekly, and manual access-control checks before each release.
Run a deeper assessment quarterly, before external VAPT and after major auth, data
or infrastructure changes. Triage relevant critical advisories the same day.
Set remediation deadlines according to exposure, exploitability and agency policy.

Maintain a system inventory with owner, repository, staging/production targets,
data sensitivity and last assessment date. Infrastructure review is separate from
application testing: include IAM, ingress, secrets, database/network exposure and
logging. Retest fixes and turn confirmed issues into regression tests.
