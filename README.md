# Matt VAPT Kit

Private, staging-first security tooling for Matthew's team. Reports are internal
self-assessments, not CERT-PH reports or certifications.

## Available in 0.5

| Component | What it actually does |
|---|---|
| Push protection | Scan committed history with Gitleaks and audit the exact pushed pnpm lockfile; optional local Semgrep rules |
| Git integration | Install/remove local pre-push hooks without replacing existing hook behavior |
| CI integration | Reusable composite action and push-to-main/staging workflow template, no PR required |
| Scoped runner | Up to ten approved paths plus header verification; optional bearer/IAP login, no redirects |
| Public exposure checks | Explicit opt-in, fixed paths and up to three source maps, bounded GET signatures with no stored bodies |
| Offline route review | Trace authentication helpers in committed Next.js API handlers and flag suspected gaps |
| Retest | Compare an earlier assessment using equivalent check evidence, never URL reachability alone |
| Role matrix | Explicitly approved DTAP logins plus read-only endpoint checks, repeated JSON-shape evidence and allowed-role controls |
| Accuracy regression corpus | Local verified-TLS fixtures with weak/safe controls, plus committed source-review fixtures |
| Report generator | CERT-PH-style HTML/PDF report, clearly marked as an MVK self-assessment, with PNG evidence figures |
| Docker tools | Core tools plus separate pinned ZAP, Nuclei, Gitleaks, Semgrep, Subfinder and testssl images |

This is **not a complete VAPT scanner**. ZAP/Nuclei discovery adapters, authenticated
object-ownership/workflow tests, infrastructure assessments and weekly schedules remain
future stages. CodeQL requires eligible repository settings and is opt-in.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
docker compose build kit
docker compose run --rm kit doctor
docker compose run --rm kit validate projects/pemedes.vapt.yml
```

Use the local CLI for Git/Docker orchestration; the core container intentionally does
not mount the Docker socket. Docker build/pull retrieves packages from their publishers.
Image digests are pinned; Debian and transitive Python packages still resolve at build
time. Update pins and revalidate regularly.

## Push checks, no PRs

```sh
.venv/bin/vapt check /path/to/project
.venv/bin/vapt check /path/to/project --static
.venv/bin/vapt hook install /path/to/project
.venv/bin/vapt hook uninstall /path/to/project
```

The pre-push hook checks every unique nondeleted pushed commit tip (including tag
targets), not just the current branch or dirty working tree. Gitleaks scans all
reachable history for each tip and redacts its output. `pnpm audit --audit-level=high`
checks a temporary copy of that commit's manifests. No dependency install, lifecycle
scripts or application build is run.
A temporary bare snapshot shares read-only Git objects during history scanning.
Local certificate directories, dirty attributes and working-tree scanner overrides
do not affect the history read. The default Gitleaks rules apply.

Checks fail closed on missing tools, unsupported Node lockfiles, audit errors and
high/critical dependency findings. Findings are not automatically fixed or ignored.
Projects without root `package.json` explicitly skip the pnpm audit; their ecosystem
auditors are not implemented yet. pnpm must resolve the exact version in the project's
`packageManager` field. The pnpm audit service receives package names and versions,
not source code. Docker scans have no network access.

Installation preserves executable hooks in the previous hooks directory and chains
the previous pre-push hook with identical stdin and arguments. Uninstall restores the
previous repository-local configuration. Keep this toolkit checkout and its virtual
environment at their installed paths. Reinstall if you move them or add new hooks to
the previous directory. Hooks are local and bypassable; CI provides another check.

### GitHub Actions

Copy `templates/push-security.yml` into the application's `.github/workflows/`, replace
`TOOLKIT_COMMIT` with a reviewed full toolkit commit SHA, and commit it. In the private
toolkit's Actions settings, permit access from repositories owned by the same user.
No personal token needs to be added to the workflow.

The workflow runs on pushes to `main` or `staging` and manually. It uses full checkout
history, minimal permissions, no persisted checkout credentials, and pinned actions.
It does not create issues containing secrets or upload raw reports as artifacts.
Results remain in the private repository's Actions logs.

CodeQL is a separate optional job, gated by repository variable `ENABLE_CODEQL=true`.
Confirm private-repository GitHub Code Security eligibility and enable code scanning
before setting it. The current PEMEDES/DTAP API reports code scanning disabled.
The three bundled Semgrep rules are a small starter set, **not equivalent to CodeQL
or comprehensive OWASP coverage**. They check explicitly disabled TLS verification,
dynamic code evaluation and interpolated shell commands. Findings require triage.

**Deployment is unchanged.** Cloud Build may deploy concurrently with these checks.
A failed advisory GitHub Action does not stop that deployment. A real release gate
must be connected to Cloud Build with separate approval.

## Project scope

`projects/pemedes.vapt.yml` contains the PEMEDES staging origin and preliminary roles.
`projects/pemedes-iap.vapt.yml` adds normal govmail sign-in and a reusable private
toolkit browser profile, without changing PEMEDES or IAP.
`projects/dtap.vapt.yml` remains unapproved for live runs. Its role matrix starts with
one read-only lead-evaluator route, derived from committed middleware and response
code. Confirm the staging host and expected policy before running it. Application
repositories may use the same format in `.vapt.yml`.

Offline validation accepts only an exact HTTPS origin on port 443, no wildcards or
embedded credentials. `environment: staging` is a declaration, not proof of isolation.
The schema is `vaptkit/schemas/project.json`. Per-role `credentials` are reserved
for future application testing and are not loaded. The optional `access` field
selects the actual gateway-access method described below.
The separate `role_testing.accounts` section uses email/password environment variable
names for the explicit role command. It does not contain credentials.

### Approve a bounded header check

```sh
.venv/bin/vapt scope-template projects/pemedes.vapt.yml > approval.local.json
```

The template is intentionally invalid. An authorized owner must set their name,
ISO-8601 start/end timestamps with timezone, and 1-10 exact paths. The scope expires
within four hours; request intervals must be 1-30 seconds. The approval is bound to
the project config's SHA-256. Changing the config requires a new approval.
`request_timeout_seconds` defaults to 30 in new templates and must be 1-60 seconds.
Old approval files without that field retain a ten-second timeout.
This is an owner attestation, not a digital signature or an authorization system.

Use synthetic staging data, an agreed test window and disabled real email/payment
side effects. HEAD requests can still invoke poorly designed application actions.
Check exclusions before approving. No production, shared cloud IPs, availability
tests or third-party reconnaissance services are in scope.

```sh
# Only after the authorized owner approves:
.venv/bin/vapt run projects/pemedes.vapt.yml \
  --approval approval.local.json --acknowledge-scope \
  --output /existing/private/folder/assessment-001
```

The header runner makes at most twenty serial HEAD requests: ten initial observations
and one verification per path with findings or baseline header findings. It requires public DNS
addresses, pins the chosen address while validating TLS against the configured host,
does not follow redirects or use proxies, and bounds socket timeouts by both the
approved timeout and the remaining approval window. It rechecks expiry after DNS,
before sending the request, and after receiving response headers.
It stops on redirects, transport/scope errors, 401/403/429 or server errors. Non-2xx responses
remain explicit coverage gaps, not passing results. Existing output directories are
never overwritten. Record and watch the assessment window; DNS resolution itself
uses the operating system resolver's timeout.

`assessment.json` stores normalized header observations, not raw headers, cookies,
response bodies or account credentials. Header presence is not proof of effective
policy. Values are graded against fixed rules. Repeated failures are marked
**confirmed**, meaning the configuration observation was reproduced, not that an
exploit succeeded. Nonreproduced findings remain **suspected**.
Data exposure and unauthorized access remain **Not tested** for this profile.
Report generation rejects a "completed" result with missing paths, failed responses
or recorded errors. Blocked responses display **Not assessed**, not misleading
missing-header observations.

### Optional public exposure checks and retest

Set `exposure_checks: true` in an approved scope file to authorize a bounded expansion
beyond its header `paths`: HEAD checks of `.env`, `.env.local`, `.env.production`,
`.git/HEAD`, `.git/config`, `/api/debug`, `/api/env`, `/api/config`, `/api/health`,
`/swagger.json`, `/openapi.json`, `/api-docs`, and a random soft-404 baseline.
Candidate responses receive a GET with `Range: bytes=0-2047`; at most 2 KB is read
even if the server ignores Range. One GET of `/` reads at most 256 KiB to discover
up to three same-origin `/_next/static/*.js.map` paths, checked with the same bounds.
There is no recursive crawling. The maximum is 52 requests including header verification.
All requests share the approval window, interval and project exclusions.

This mode requires a configuration **without `access` credentials**. Access through
IAP or an application account cannot establish that a file is publicly accessible.
The runner stops on redirects, 401/403, rate limits, server errors or transport failures,
retaining partial evidence. No redirect is followed and no returned URL is fetched.
Bodies and credentials are never saved. Signature matches confirm exposed environment
files, Git metadata or source maps; diagnostic output and API documentation remain
suspected because their public availability may be intentional.

Soft-404 matching and small content samples are conservative heuristics. They can miss
real exposures, including files with unexpected content types or signatures beyond
the read limit. No matching signature is not an all-clear. Exposure coverage refers
only to this finite list, not every API response or sensitive-data flow.

```sh
.venv/bin/vapt run projects/dtap.vapt.yml \
  --approval approval.local.json --acknowledge-scope \
  --baseline /private/previous/assessment.json --output /private/retest-001
```

A baseline must match the project, exact target and access profile. Reports show
**Still present**, **Resolved**, or **Not rechecked**. Header fixes need two successful
observations of the same check; missing newer check fields do not imply a fix.
An exposed file is marked resolved only when its exposure recheck returns 404/410.
Source-review findings, excluded checks, blocked responses and inconclusive results
are not automatically resolved. Keep baseline files private and review the evidence.

### Offline API authentication review

```sh
.venv/bin/vapt review-routes projects/dtap.vapt.yml /path/to/DTAP \
  --revision HEAD --output /private/dtap-routes.json
.venv/bin/vapt report /private/assessment/assessment.json \
  --source-review /private/dtap-routes.json --reviewed --output /private/report
```

Only committed Git objects are read; dirty application files are not scanned or
modified. Public-route allowlists, privileged prefixes and custom authentication
patterns live under `review` in the toolkit project config. Helper tracing is bounded
and heuristic, not a full TypeScript control-flow analysis. Every source-review
finding remains **suspected** until checked against middleware and live authorized
behavior. Seeing an auth helper does not prove that every execution path enforces it.

### Approved DTAP role matrix

`vapt roles` supports the existing DTAP cookie login contract only. It is not a
generic login crawler and it does not support PEMEDES or IAP role login yet.
The account aliases distinguish the two evaluators while keeping both in the
`evaluator` role. Testing two accounts does not by itself test record ownership.

```sh
.venv/bin/vapt scope-template projects/dtap.vapt.yml --roles > roles.local.json
# Owner supplies an active window and sets role_login to true after reviewing scope.
# Load account emails and passwords into the configured environment variables locally.
# Never put their values in Git, CLI arguments, report notes, or shell history.
.venv/bin/vapt roles projects/dtap.vapt.yml \
  --approval roles.local.json --acknowledge-scope --output /private/dtap-roles-001
```

Approval binds the config digest, exact GET paths and selected account IDs.
Each route must have an approved allowed-role account as a positive control.
The command checks anonymous access, logs in once per account, verifies the returned
email and role, uses that account's isolated `auth-token` and `session-bind` cookies,
and requests sign-out afterwards. No login retries are made. Only sign-in and sign-out
receive POST requests. **Login is not side-effect-free:** it creates sessions and audit
records and can change login counters. Obtain permission for these effects even when
business records must remain unchanged. GET handlers must also be reviewed for side effects.

Unexpected 2xx responses become **confirmed endpoint role-policy violations** only
when both repeated responses match the configured JSON response shape and an
allowed-role control succeeds. Generic login pages, JSON errors, truncated bodies and
missing controls never confirm access. The response schema is an operator-reviewed
oracle, not proof that every returned record is sensitive or belongs to another user.
Only status, content-type class and shape-match booleans are retained, not bodies.

401/403 on matrix GETs are expected denials. On login they stop the run.
Redirects, rate limits, 5xx responses, transport errors and scope expiry stop all
further traffic, including logout. Such sessions are marked **unconfirmed cleanup**;
an operator may need to revoke them manually. A logout success response records only
acknowledgement, not independently proven revocation. The maximum is 196 requests
for eight accounts and ten routes, all serial and inside the approved interval/window.
Do not run against production or change application/infrastructure configuration
to force the checks to pass.

### Accuracy benchmark and limitations

```sh
.venv/bin/python -m unittest discover -s tests -p test_accuracy_benchmark.py
.venv/bin/python -m unittest discover -s tests -p test_routes.py
.venv/bin/python -m unittest discover -s tests
```

The benchmark requires local `openssl`. It starts a temporary loopback HTTPS server
with a test certificate, uses the real pinned request transport and report pipeline,
and replaces public DNS/socket destinations only inside the test process. It never
contacts DTAP or PEMEDES. The fixtures include header-value boundary cases, duplicate
CSP policies, script directive overrides, malformed HSTS, soft-404 pages, exposed
files, minimal health responses, ignored Range headers, isolated role sessions,
intentional role-policy bypasses and misleading 200 responses.

Each run prints true positives, false positives, true negatives and false negatives
for the HTTP corpus. The synthetic source review prints finding-level TP/FP/FN.
The regression gate requires zero false positives and misses **on this finite corpus**.
That is not a measured production accuracy percentage or a guarantee of no
vulnerabilities. Source tracing, cookie-name classification, CSP policy interactions,
small exposure signatures and configured JSON response shapes remain heuristic.
Human review and authorized real-application testing are still required before
sharing the toolkit as a trusted assessment tool.

### Access through Google IAP

Do not disable IAP or alter IAM just to obtain a passing assessment.
A normal `gcloud auth print-identity-token` token is not necessarily accepted:
IAP programmatic access may require a configured client allowlist. The toolkit
does not create that allowlist or grant permissions.

For ordinary browser/govmail login:

```sh
.venv/bin/pip install -e '.[report]'
.venv/bin/playwright install chromium
.venv/bin/vapt scope-template projects/pemedes-iap.vapt.yml > approval.local.json
# Fill the approved owner, time window and exact paths. For example, /api/health and /.
.venv/bin/vapt run projects/pemedes-iap.vapt.yml \
  --approval approval.local.json --acknowledge-scope \
  --output /existing/private/folder/pemedes-001
```

Sign in yourself in the toolkit's browser. The toolkit never fills password/MFA
fields, records the login screen, or reads your regular browser's profile. Only
the configured origin's secure IAP cookies are selected for scoped HEAD requests.
Application cookies are not forwarded. The browser closes before those checks.

`access: {type: iap-browser, remember_login: true}` reuses a separate, origin-specific
profile under `$XDG_STATE_HOME/matt-vapt-kit/iap-browser/` (normally
`~/.local/state/matt-vapt-kit/iap-browser/`). Profile directories are mode 0700 and
are outside Git and reports. **This profile contains sensitive Google login state.**
Its contents are not guaranteed to be encrypted. Secure the workstation and never
upload or share it. Google may still require reauthentication after expiry or revocation.
Only one process may use the same profile at a time.

For one-off use, omit `remember_login` or set it to `false`; the login profile is
temporary. Changing it creates a different config digest, so regenerate approval.
To forget a saved login, close its toolkit browser and delete only the specific
origin-hash directory, or sign out through that browser. Do not delete unrelated profiles.

Login itself involves ordinary browser navigation and Google sign-in requests,
separate from the assessment's HEAD request budget. It may refresh Google's
session cookies. The login browser blocks non-GET/HEAD application requests except
IAP's own authentication callback, honors excluded application prefixes, and blocks
third-party origins other than Google's login resources. It is not a crawler.
Do not use it to log into application accounts or perform application actions.
The interactive window waits up to five minutes or approval expiry, whichever comes first.

For an already-approved programmatic client instead:

```yaml
access:
  type: bearer
  token_env: VAPT_IAP_TOKEN
  header: Proxy-Authorization
```

Supply the short-lived token in that environment variable, never YAML or CLI arguments.
Use `Authorization` instead only when the application's approved authentication
mechanism requires it. The config/approval bind this choice to the exact target.
Missing/invalid credentials fail before network traffic. Tokens are not logged or
saved in assessment/report artifacts. HTTP 401/403 remains an incomplete result.

Compose defaults to no networking. Enabling network access for the core container
requires an explicit override and does not waive CLI scope checks. Scanner containers
are dormant tools, not scheduled assessments.

## Your report, with screenshots

Build the separate offline browser-export image:

```sh
docker compose --profile report build report
```

Review the assessment JSON for personal data and secrets before export. The toolkit
retains only selected metadata, but manual input can still contain sensitive text.
`--reviewed` records your acknowledgement, not a claim of perfect automatic redaction.

```sh
# Replace both mounts with existing, private directories.
docker compose run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v /private/assessment-001:/input:ro \
  -v /private/reports:/output \
  report report /input/assessment.json --output /output/report-001 --reviewed \
  --agency "DICT" --prepared-by "Your Name" --tlp AMBER+STRICT
```

### Report format (MVK-SAR)

The layout follows the structure of a CERT-PH penetration testing report so results
read the same way as the external VAPT: cover page, report details and sign-off,
1 Executive Summary (synopsis, scope, methodologies), 2 Key Findings (findings table,
severity chart, coverage, OWASP Top 10 2025 mapping), 3 Recommendation,
4 Vulnerability Findings (4.1 reconnaissance with evidence figures, 4.2 findings by
severity with Solution and Affected Links/Assets, 4.3 attack and exploitation),
5 Clean-up, 6 Disclaimer, and Appendices A (severity), B (OWASP), C (TLP),
D (searchable evidence record).

Every file is marked as ours so it can never be mistaken for a CERT-PH report:

- `MVK` badge and amber **"MATT VAPT KIT | INTERNAL SELF-ASSESSMENT | NOT ISSUED BY CERT-PH"** cover ribbon.
- Diagonal **"MATT VAPT KIT | SELF-ASSESSMENT"** watermark on every page.
- Report ID `MVK-<PROJECT>-<YYYYMMDD>-<scope hash>` on the cover, details table and footer.
- PDF footer: `MVK-SAR v<version> | <report ID> | Matt VAPT Kit self-assessment, not a CERT-PH report`.

No CERT-PH logos, signatures, ticket numbers, analyst names or verbatim boilerplate
are reproduced. `--tlp` (default `AMBER+STRICT`), `--prepared-by` and `--agency`
fill the classification and details table; labels are limited to 120 printable
characters and HTML-escaped. Dates are shown in PHT (UTC+08:00).

Findings may carry optional `owasp` (`A01`-`A10`) and `cvss` (`version`, `score`,
`vector`) fields. A CVSS score must match its severity band and vector version or
the report is rejected. Unscored findings show "(not scored)". Configuration
findings default to A02 and unauthorized-access findings to A01; data-exposure
findings without an explicit category are counted as "Not mapped".

Outputs: `report.html`, `report.pdf`, and `evidence-01.png` (one PNG per observation).
The PNGs are real Chromium screenshots of **rendered, sanitized HTTP evidence**,
not screenshots of the target website. Each has a caption and hash. Website capture
and arbitrary scanner-output import are not implemented yet.

HTML is self-contained with embedded screenshots; PDF is tagged and searchable.
Chromium is network-disabled in Docker, external page requests are blocked, and
report content is HTML-escaped. Reports use no remote fonts, scripts or images.
Folders are mode 0700 and files 0600. No encryption is applied; choose appropriate
encrypted storage and share only with authorized recipients.

For HTML without browser dependencies:

```sh
.venv/bin/vapt report /private/assessment-001/assessment.json \
  --output /private/reports/html-001 --reviewed --html-only
```

For local PDF/PNG export instead of Docker, install `.[report]`, then
`.venv/bin/playwright install --with-deps --only-shell chromium`.

Section 2 answers **"Was data exposure found?"** and **"Was unauthorized access found?"**
with **Confirmed**, **Suspected**, **Not observed in tested scope**, or **Not tested**.
A clean vulnerability scan does not prove that a historical leak never occurred.
Methodologies not run are listed as "Not performed". No CVSS score is invented.
Manual findings can use the same strict JSON schema; arbitrary raw scanner reports
are rejected.

## Private evidence and interpretation

Keep reports, approvals, screenshots, cookies and personal data out of Git. Ignore
rules are guardrails, not access control. Do not share code or assessment data with
external scanning services. External-provider reconnaissance remains disabled.

Public JavaScript/API route names are normal web behavior, not automatically source
disclosure. `NEXT_PUBLIC_*` variable names alone do not establish an authentication
bypass. Verify actual server-side enforcement and impact. Minimal public liveness
checks can be appropriate; internal diagnostics need separate controls.

## Verification and cadence

```sh
.venv/bin/python -m unittest discover -s tests -v
docker compose run --rm kit doctor
```

`tests/fixtures/assessment.json` is synthetic and labeled as such in exports.
The suite includes a local HTTPS server with a temporary certificate to exercise
successful requests, rejected credentials, redirects, and report export through
the real HTTP client. It requires `openssl`. No live application or Google login
is contacted by the test suite or the toolkit CI.

Use push checks on every push, daily advisory monitoring, and manual access-control
review before releases. Weekly approved staging scans and quarterly deeper VAPT are
the planned next layer, not jobs already scheduled. Assess major auth/data/infra
changes and relevant critical advisories promptly, then retest every confirmed fix.
Maintain an inventory of owners, targets, sensitive data and assessment dates.
