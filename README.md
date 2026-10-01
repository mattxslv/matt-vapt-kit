# Matt VAPT Kit

Private, staging-first security tooling for Matthew's team. Reports are internal
self-assessments, not CERT-PH reports or certifications.

## Available in 0.3

| Component | What it actually does |
|---|---|
| Push protection | Scan committed history with Gitleaks and audit the exact pushed pnpm lockfile; optional local Semgrep rules |
| Git integration | Install/remove local pre-push hooks without replacing existing hook behavior |
| CI integration | Reusable composite action and push-to-main/staging workflow template, no PR required |
| Scoped runner | Up to ten approved HTTPS HEAD requests; optional bearer/IAP login, no assessment redirects, bodies or crawling |
| Report generator | Original light HTML/PDF briefing and PNG screenshots of sanitized observations |
| Docker tools | Core tools plus separate pinned ZAP, Nuclei, Gitleaks, Semgrep, Subfinder and testssl images |

This is **not a complete VAPT scanner**. ZAP/Nuclei discovery adapters, authenticated
role/ownership/workflow tests, infrastructure assessments and weekly schedules remain
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
`projects/dtap.vapt.yml` is a draft; its target did not respond during setup and roles
need review. Application repositories may use the same format in `.vapt.yml`.

Offline validation accepts only an exact HTTPS origin on port 443, no wildcards or
embedded credentials. `environment: staging` is a declaration, not proof of isolation.
The schema is `vaptkit/schemas/project.json`. Per-role `credentials` are reserved
for future application testing and are not loaded. The optional `access` field
selects the actual gateway-access method described below.

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

The local runner makes a maximum of ten serial HEAD requests. It requires public DNS
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
policy. Missing defense headers are observations, not demonstrated exploits.
Data exposure and unauthorized access remain **Not tested** for this profile.
Report generation rejects a "completed" result with missing paths, failed responses
or recorded errors. Blocked responses display **Not assessed**, not misleading
missing-header observations.

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
  report report /input/assessment.json --output /output/report-001 --reviewed
```

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

The first page distinguishes **Confirmed**, **Suspected**, **Not observed in tested
scope**, and **Not tested**. A clean vulnerability scan does not prove that a historical
leak never occurred. No CVSS score is invented. Manual findings can use the same strict
JSON schema; arbitrary raw scanner reports are rejected.

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
