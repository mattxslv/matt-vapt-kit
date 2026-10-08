# Command and assessment reference

[Back to the README](../README.md) | [First-time setup](getting-started.md) | [Team pilot](pilot-checklist.md)

Detailed behavior, scope limits and interpretation rules for Matt VAPT Kit.
Run command examples from the repository root. Placeholder paths must be replaced
with existing private directories. Project configurations are not authorization.

## Contents

- [Setup](#setup)
- [Push checks and GitHub Actions](#push-checks-no-prs)
- [Project scope and approvals](#project-scope)
- [Exposure checks and retests](#optional-public-exposure-checks-and-retest)
- [Offline API review](#offline-api-authentication-review)
- [Cloud Armor metadata and local XSS lab](cloud-armor-and-xss.md)
- [DTAP role matrix](#approved-dtap-role-matrix)
- [Accuracy benchmarks](#accuracy-benchmark-and-limitations)
- [Release challenge](#separate-release-challenge)
- [Ownership and workflow lab](#local-ownership-and-approval-workflow-lab)
- [Independent application cross-check](#independent-application-cross-check)
- [Google IAP access](#access-through-google-iap)
- [Reports](#your-report-with-screenshots)
- [Private evidence](#private-evidence-and-interpretation)

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

For an interactive all-supported-checks workflow:

```sh
./scan /path/to/project
./scan /path/to/project --config projects/dtap.vapt.yml
```

This runs secret history, a lockfile dependency audit, bundled static rules and
offline route review against one pinned HEAD revision. Independent stages continue
after a failure so the final table does not hide coverage gaps. It writes only
normalized stage statuses, static-match locations and route-review evidence,
not raw scanner logs. Static matches are grouped by rule in the terminal;
`static-findings.json` contains every location without source snippets.
Exit zero means all stages returned normally; one means review or missing coverage;
two means setup/argument failure. Non-Node dependency coverage is explicitly
unsupported. Default route heuristics have no project public-route allowlist;
use `--config` for reviewed project policy. Source findings remain suspected.

The existing fail-closed `check` command and hooks retain their previous behavior:

```sh
.venv/bin/vapt check /path/to/project
.venv/bin/vapt check /path/to/project --static
.venv/bin/vapt hook install /path/to/project
.venv/bin/vapt hook uninstall /path/to/project
```

The pre-push hook checks only the commits a push adds (`remote..local`, or the new
commits of a new branch), not the dirty working tree. Gitleaks scans those commits and
redacts its output. When a lockfile or manifest changed, the dependency audit checks the
committed lockfiles of the pushed tip. No dependency install, lifecycle scripts or
application build is run.
A temporary bare snapshot shares read-only Git objects during history scanning.
Local certificate directories, dirty attributes and working-tree scanner overrides
do not affect the history read. The default Gitleaks rules apply.

New leaked secrets and high/critical dependency findings block the push; a check
that cannot run (for example Docker is off) warns and lets the push through. Findings
are not automatically fixed or ignored.

The dependency audit uses OSV-Scanner on the committed lockfiles: npm, yarn, pnpm and
bun for Node; Composer for PHP; NuGet (`.csproj`, `packages.config`, `packages.lock.json`) for .NET; pip, Poetry, Pipenv and uv for Python; Go, Maven,
Gradle, Ruby and Rust. Lockfiles under `node_modules/`, `vendor/` and virtualenvs are
skipped. No package manager needs to be installed. Each vulnerable package is classified
from the lockfile as runtime or dev-only (pnpm: reachable from `dependencies`; npm: the
`dev` flag; Composer: `packages-dev`); only runtime high/critical results make the step
REVIEW or block a push. Packages that can't be classified (yarn, NuGet) count as runtime. Package names and versions (not
source code) are sent to osv.dev; the other Docker scans have no network access.

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
before setting it. Check each application's current eligibility and settings.
The bundled Semgrep rules are a small starter set, **not equivalent to CodeQL
or comprehensive OWASP coverage**. Findings require triage.

| Language | Rules |
|---|---|
| JavaScript / TypeScript | disabled TLS verification, dynamic code evaluation, interpolated shell commands |
| C# / ASP.NET | SQL built from strings (SqlCommand, CommandText, EF raw SQL), processes started with built strings, uploads saved under the client's filename, hardcoded passwords/keys/connection-string passwords, developer error page outside development |
| web.config / appsettings | debug compilation on, customErrors Off, request validation off, passwords in connection strings |

The JavaScript rules skip bundled libraries (`*.min.js`, `wwwroot/lib*`, `Scripts/jquery*`).
Matches in `scripts/`, `migrations/`, `tests/`, `docs/` and `*.test.*` files are listed as
outside the running app and don't make the step REVIEW. Files Semgrep only partly parsed
(for example JSX text containing `&`) are noted but don't count as missing coverage.
On nopCommerce (about 3,700 C# files) the C# rules report three SQL strings built from
configuration values and one developer error page enabled by a config flag, all worth review.

**Deployment is unchanged.** Cloud Build may deploy concurrently with these checks.
A failed advisory GitHub Action does not stop that deployment. A real release gate
must be connected to Cloud Build with separate approval.

## Project scope

`projects/pemedes.vapt.yml` contains the PEMEDES staging origin and preliminary roles.
`projects/pemedes-iap.vapt.yml` adds normal govmail sign-in and a reusable private
toolkit browser profile, without changing PEMEDES or IAP.
`projects/dtap.vapt.yml` is not a standing approval for live runs. Its role matrix starts with
one read-only lead-evaluator route, derived from committed middleware and response
code. Confirm the staging host and expected policy before running it, even after
a previous successful pilot. Application
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

**Next.js middleware** is modeled: the kit follows `middleware.ts` into the modules it
imports and recognizes a public-routes array, a 401 for requests without a valid token,
and `[/^\/api\/.../, roles]` role rules. Handlers covered by them count as protected
("protected by the middleware" in the summary) instead of being flagged. Handlers that
**write using a user ID taken from the request** (body, query or JSON) without comparing
it to the signed-in user are flagged as possibly changing someone else's record; admin
endpoints (`/admin/` paths and `privileged_prefixes`) are exempt.

**ASP.NET (C#)** is reviewed in the same run. Controllers (MVC and Web API, Core and
.NET Framework) are protected by `[Authorize]` on the action, the controller or any base
controller, by custom attributes with `Authorize` in their name (add others with
`review.auth_attributes` regexes), by checks in the action body (`User.IsInRole`,
`IsAuthenticated`, `AuthorizeAsync`, permission-service calls), or by a global filter,
fallback policy or `MapControllers().RequireAuthorization()`. `[AllowAnonymous]` marks
an action public. Minimal APIs count `.RequireAuthorization()`, authorized route groups
and `[Authorize]` on the handler lambda. Routes come from `[Route]`/`[HttpGet("...")]`
templates, or `/Controller/Action` for conventional routing. WebForms pages and Razor
Pages conventions are not reviewed. On nopCommerce all 620 admin actions are recognized
as protected; the remaining unprotected actions are its public storefront.

### Approved DTAP role matrix

`vapt roles` supports the existing DTAP cookie login contract only. It is not a
generic login crawler and it does not support PEMEDES role login.
The account aliases distinguish the two evaluators while keeping both in the
`evaluator` role. Testing two accounts does not by itself test record ownership.

```sh
mkdir -m 700 .private
.venv/bin/vapt scope-template projects/dtap.vapt.yml --roles > .private/role-approval.json
# Owner supplies an active window and sets role_login to true after reviewing scope.
# Load account emails and passwords into the configured environment variables locally.
# Never put their values in Git, CLI arguments, report notes, or shell history.
.venv/bin/vapt roles projects/dtap.vapt.yml \
  --approval .private/role-approval.json --acknowledge-scope \
  --prompt-passwords --output .private/dtap-roles-001
```

`--prompt-passwords` is optional. It requests missing QA passwords in an
interactive terminal without echo, once per distinct configured password variable.
Email variables must already be set. Existing password environment values are used
unchanged, so automation remains compatible without the flag. Prompted values stay
in memory and are never exported to the process environment or written to files.
The runner checks scope before and after prompting and rejects cancelled input,
noninteractive input or an unsafe echo fallback without assessment traffic.

For DTAP staging behind Google IAP, make a private copy of the toolkit project
configuration and add `access: {type: iap-browser, remember_login: true}`.
Generate a new role approval from that exact configuration, then use it with
`vapt roles`. The normal browser sign-in opens before matrix requests and uses
the same approval window. Browser navigation and Google sign-in traffic are
additional to the bounded matrix requests below. Install the optional browser
dependencies described under IAP login. Bearer gateway access is not supported
by the role runner.

Only target IAP cookies are shared across requests. DTAP account cookies remain
isolated and are never collected from the browser. With IAP enabled, "anonymous"
means no **DTAP application session**, not anonymous internet access: that control
still authenticates at the gateway. The report records this limitation.
Gateway redirects stop the run without retrying or following them. A denied
gateway request cannot establish successful application coverage without the
allowed-role positive control. DTAP sign-out does not revoke the IAP session;
`remember_login: true` retains the private browser profile for future use.

Approval binds the config digest, exact GET paths and selected account IDs.
Each route must have an approved allowed-role account as a positive control.
The command checks anonymous access, logs in once per account, verifies the returned
email and role, uses that account's isolated `auth-token` and `session-bind` cookies,
and requests sign-out afterwards. No login retries are made. Only sign-in and sign-out
receive POST requests. **Login is not side-effect-free:** it creates sessions and audit
records and can change login counters. Obtain permission for these effects even when
business records must remain unchanged. GET handlers must also be reviewed for side effects.

Unexpected 2xx responses become **confirmed endpoint role-policy violations** only
when both repeated responses match the configured JSON response shape, configured
arrays are nonempty, no cache-hit signal is observed, and an allowed-role control
meets those same evidence requirements. Generic login pages, JSON errors, truncated
bodies, empty datasets and missing controls never confirm access. Empty pages remain
inconclusive even if they advertise a next page; pagination links are never followed.
The response schema is an operator-reviewed
oracle, not proof that every returned record is sensitive or belongs to another user.
Only status, content-type class, shape-match booleans and derived evidence-quality
labels are retained, not bodies. An observed `Age` greater than zero or cache-hit
indicator (`X-Cache` or `CF-Cache-Status`) makes the response inconclusive for
role enforcement. Missing cache indicators do not prove origin freshness.

An anonymous 401 or a 403 can establish an observed denial only with an assessable
JSON error response, not an HTML gateway page or a successful data envelope.
This does not prove which layer enforced the denial. A 401 after account login
could mean session expiry, so it blocks the run instead of passing a role check.
Non-JSON 401/403 responses also block the run. On login, any 401/403 stops the run.
Redirects, rate limits, 5xx responses, transport errors and scope expiry stop all
further traffic, including logout. Such sessions are marked **unconfirmed cleanup**;
an operator may need to revoke them manually. A logout success response records only
acknowledgement, not independently proven revocation. The maximum is 196 requests
for eight accounts and ten routes, all serial and inside the approved interval/window.
Do not run against production or change application/infrastructure configuration
to force the checks to pass.

Reports distinguish **tested**, **blocked**, **inconclusive** and **not run** matrix
cells, including approved cells that were never reached. Generic success pages are
coverage gaps, not vulnerability findings. Partial matching evidence can still be a
suspected finding, but never a passing matrix. Record ownership and approval
workflows are explicitly unsupported in live assessments. Older report records
without evidence-quality labels retain their original status/shape interpretation
and are labeled as legacy evidence, not silently upgraded to the newer criteria.

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

### Separate release challenge

```sh
PYTHONPATH=tests .venv/bin/python -m unittest discover -s release_tests -v
```

Run this separately before tagging a release. The `Release challenge` GitHub workflow
also runs on `v*` tags or manual dispatch, not on routine branch pushes. No workflow
publishes or deploys the toolkit. Missing OpenSSL fails this gate rather than
silently skipping it.

`release_tests/role_cases.json` is a versioned expected-outcome manifest, separate
from the challenge server and production classification code. Its 17 cases cover
HTML/JSON login responses returning 200, error envelopes, empty data, pagination,
cache indicators, inconsistent responses, expired sessions, gateway denials,
redirects, rate limits, oversized bodies and missing usable controls. The server
uses temporary loopback HTTPS, synthetic accounts and no live target input.
Requests to pagination links or redirect destinations are forbidden by the gate.
The suite also exercises private JSON and HTML reports and checks for fixture-data
leaks.

Every case must match its expected outcome, not just avoid confirmed findings.
Version 1 expects 2 confirmed role violations, 1 assessed denial, 10 inconclusive
cases and 4 blocked cases. Inconclusive and blocked cases are not counted as safe
true negatives. These are **locally authored challenge regressions, not a blind
or statistically independent holdout**. They were inspected while improving the
detector. A genuine held-out evaluation needs a separately maintained, unseen
corpus; once a case is used to tune detection it becomes a regression case.
Do not change expected outcomes merely to make a release pass. Review oracle
changes explicitly and version substantive corpus revisions.

### Local ownership and approval-workflow lab

```sh
.venv/bin/python -m unittest discover -s tests -p 'test_authorization*.py'
```

This local-only lab starts a temporary loopback HTTPS server. Four synthetic users
exercise private and shared documents, peer access, edits, draft submission, lead
review and director approval. The safe application enforces ownership, separation
of duties and `draft -> submitted -> reviewed -> approved` ordering. Deliberately
flawed modes omit individual controls. No live app configuration is accepted,
no real credentials are loaded and all sessions and records disappear at teardown.

`vaptkit.authorization` evaluates derived evidence without sending requests.
Reads require an owner positive control and two matching object IDs, owners and
private synthetic markers, not just matching JSON shape. Writes need independent
before/after reads showing the expected object, phase, one revision increment,
actor and action. Repetitions use fresh synthetic records. Even an HTTP error is
flagged when its body discloses the protected object or readback proves a forbidden
state change. Generic successes, missing controls, wrong objects, uncertain
attribution and unreadable bodies remain **inconclusive**, not passing controls.

The 34-case outcome manifest is maintained separately from the application and
detector. It currently yields 10 detected violations, 15 correct allowed/denied
controls and 9 explicitly inconclusive cases. The fixture also exercises the full
valid workflow and verifies revoked sessions actually stop working.
The scenarios follow [OWASP WSTG IDOR guidance](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
and [workflow-circumvention guidance](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows).
This is reference-backed, locally authored coverage, not independent certification.

**These ownership/workflow checks are not wired into `vapt roles` or live reports.**
Live ownership mapping, permitted state changes and independent readback would need
separate project-specific adapters and explicit approval. Current live reports still
correctly say that ownership and workflows were not tested.

### Independent application cross-check

An optional test uses unmodified **OWASP Juice Shop v19.0.0**, pinned by image digest.
It creates two synthetic accounts and a basket, establishes the owner's control,
then repeats access with the other account. The application and known basket-access
flaw are independently maintained; our evidence adapter and assertions are ours.

```sh
docker pull bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d
MVK_RUN_JUICE_SHOP=1 .venv/bin/python -m unittest discover -s tests -p test_juice_shop_benchmark.py
```

Pulling the public image requires internet access. The test itself uses
`--pull=never --network none`, no published ports, no host mounts, no extra capabilities,
and CPU/memory/PID limits. HTTP requests run inside the container against its own
loopback interface. The test stops and removes only the container it created.
It does not run automatically with the default suite.

The observed external control is correct owner access and a confirmed cross-account
basket read. Anonymous requests return 401, but their non-JSON bodies are deliberately
**inconclusive** for our object-evidence adapter. That limitation is not counted as a
successful assessed denial. This is one externally maintained application and one
vulnerability class, not an independent evaluation of every toolkit feature or workflow.
The local HTTPS lab, rather than this container, exercises the toolkit's TLS transport.

### Fresh-install walkthrough (local only)

From a clean checkout of a reviewed toolkit commit:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[report]'
.venv/bin/vapt --version
.venv/bin/vapt validate templates/project.example.yml
.venv/bin/python -m unittest discover -s tests
.venv/bin/python -m playwright install chromium
mkdir -m 700 .private
.venv/bin/vapt report tests/fixtures/assessment.json --reviewed \
  --output .private/synthetic-report
```

Requirements: Python 3.11+, Git, OpenSSL, and Chromium's system libraries for PDF
export. Missing OpenSSL skips local HTTPS tests, so review skip messages rather than
treating a reduced suite as full coverage. Docker is needed only for the optional
external-app benchmark and existing container tools. Installation and browser download
contact package publishers; tests do not contact application staging hosts.
If Chromium or its libraries are unavailable, `--html-only` supports offline HTML
export but does not validate PDF export. Never reuse an existing output directory.
The included report fixture is synthetic and cannot establish any project's security.

### Access through Google IAP

For approved unattended access, the toolkit supports a dedicated keyless service
account instead of browser login:

```yaml
access:
  type: iap-service-account
  service_account: your-pilot@your-staging-project.iam.gserviceaccount.com
```

Use this in a private project configuration and generate a new approval for its
exact digest. Both `vapt run` and `vapt roles` support it. The account must already
have `roles/iap.httpsResourceAccessor` on the specific staging IAP resource, and the
current gcloud identity must have permission to sign JWTs for that account
(`roles/iam.serviceAccountTokenCreator` on that service account only). The IAM
Credentials API must be enabled. Provisioning these is an explicit administrator
action, never an automatic runner action. Do not reuse a production or
secret-management identity.

The adapter calls `gcloud auth print-access-token` with captured output, then the
Google IAM Credentials `signJwt` API over verified, pinned HTTPS. JWTs are scoped
to the configured origin, expire within five minutes and never outlive the
approval. They are refreshed when less than 30 seconds remain, with approval
revalidated before every use. Tokens are kept in process memory, not files,
arguments or report output. Configured application credential variables are
removed from the gcloud subprocess environment. No service-account key files
are accepted or created.

The signed JWT uses `Proxy-Authorization`; DTAP application cookies remain
separate and isolated per account. This avoids Google browser prompts, **not the
need for DTAP QA credentials**. Signing errors stop the assessment without
retrying or falling back to another identity. IAM credential requests are
additional to the bounded application request count. Current browser-login
and bearer-header behavior is unchanged; arbitrary bearer role testing remains
unsupported.

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
- Diagonal **"MATT VAPT KIT"** watermark centered on every page.
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
.venv/bin/vapt doctor --for roles --config .private/project.yml
```

Task-specific doctor profiles are documented in [setup](getting-started.md).
Assessment commands now print a compact coverage/cleanup summary after saving
JSON. Exit codes are unchanged: zero means the scoped run completed, **not that
there were no findings**; one indicates an incomplete run and two a command/setup
error. Report generation remains explicit and requires `--reviewed`.

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
