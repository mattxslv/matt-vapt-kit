# Matt VAPT Kit — Handoff

**Date:** 2026-10-12 (session via Claude Code, latest session)

## What this session added (2026-10-12, latest)

Current version: **v0.8.7**. 383 Python tests pass
(`.venv/bin/python -m unittest discover -s tests`).

### Human-readable evidence folder names (user-caught UX issue) + "open both" option
User saw a real scan's output path (`scan-20261012-053127-469498`) and pointed out, fairly,
that nobody's going to remember or recognize a folder named after random digits when they go
looking for it later. All five places that generated an evidence folder name
(`scan_branches`/`show_drift`/`run_staging_check`/`run_local_attack` in `menu.py`, and `scan()`'s
own default-output path in `scan.py`) built names as `{prefix}-{timestamp}-{6 hex}`, with nothing
project-identifying in them at all.

Added two small shared helpers in `scan.py`: `project_slug(name)` (lowercase, hyphenated,
collapsed-repeat-dashes, bounded to 64 chars - extracted from logic that already existed inline
for the no-config fallback project name) and `dated_folder(parent, *parts)` (joins slugified
parts with a timestamp and a short 4-hex collision-guard suffix). Every call site now names
folders like `scan-dtap-staging-20261012-053751-f301`,
`quick-dtap-test-20261012-...` (reuses the project name `staging_config()` already derives from
the host, instead of the generic literal "quick-staging-..." it was using before), and
`attack-localhost-3000-20261012-...` instead of opaque digit-only names. Verified end to end
(not just unit tests): ran a real `vapt scan` against the DTAP repo with and without `--output`
and confirmed the default path produces `scan-dtap-20261012-053911-521f`.

Also added, from the same screenshot conversation: the "press r to open the report(s), f to open
the folder(s)" prompt (`offer_open` in `menu.py`) only let you pick one or the other - added `b`
for both. 4 new tests in `test_menu.py` (`OfferOpenTests`: r-only, f-only, b-opens-both with the
right call count, Enter opens nothing).

Removed the now-dead `import uuid` from `menu.py` (every direct `uuid.uuid4()` call site was
replaced by `dated_folder`, which handles its own short suffix internally).

### Fixed a real gitleaks silent-undercounting bug (found by a peer session, verified independently)
A separate Claude session working the DTAP incident reported that the vaptkit secret-history
wrapper undercounts commits on a large repo. Verified this independently against the real repo
before trusting it (the peer's first two claims in the same exchange turned out to need
correction - a stale GitHub-mirror remote check, and a misattributed branch for the secrets count
- so this one got the same scrutiny): confirmed `/home/tonky/repos/dtap`'s `origin/staging` has
1483 commits by plain `git rev-list`, reproduced the exact wrapper invocation (mirror clone +
`docker_repo()`'s mount flags) against the real pinned gitleaks image, and got the identical
result - **"1232 commits scanned."**, zero errors or warnings printed, silently stopping 251
commits short and missing real secrets that only existed in the unwalked tail. Root cause is
inside gitleaks's own git-log piping (no shallow clone, no grafts, no `--first-parent`/`--no-merges`
explanation fit the exact number) - not something to fix upstream from here, but something this
kit must never trust blindly.

Fixed in `checks.py::history_findings()` (used by `vapt check`, `vapt scan`, and CI - the
full-history audit path, where "no leaks found" is a claim about the *entire* repo): after
cloning the mirror, compute the real expected commit count with `git rev-list --count sha` on the
mirror itself, parse gitleaks's own "N commits scanned." line from its stderr, and raise a
`ToolError` - not a quiet pass - the moment the two numbers disagree, or the line is missing
entirely. Verified end to end against the real DTAP repo after the fix: `vapt check
/home/tonky/repos/dtap --revision origin/staging` now correctly fails with "Secret history scan
covered 1232 of 1483 commits reachable from e4a7443fed92; the scanner stopped early. Results are
incomplete and have been withheld." instead of silently reporting clean.

Deliberately NOT applied to `scan_history()` (the pre-push hook's bounded, new-commits-only scan):
that path streams gitleaks's output live to the terminal via the plain `run()` helper instead of
capturing it, for real-time push feedback; adding the same check would mean capturing output and
losing that live streaming UX. The push hook only ever scans the commits being pushed (small,
bounded), not a repo's entire history, so it's a fundamentally smaller-scale operation less likely
to trip this - flagging as a known, narrower-scope gap rather than changing streaming behavior
without being asked. `vapt check`/full scans remain the authoritative "is this repo's history
clean" answer, which is exactly the path this fix covers.

2 new tests in `test_checks.py` (`test_undercounted_commit_scan_is_rejected_not_reported_as_clean`,
`test_missing_commits_scanned_line_is_also_rejected`) plus 3 existing tests
(`HistoryFindingsTests`, two in `PushTests`) updated to include a realistic "N commits scanned."
line in their mocked gitleaks stderr, since they previously mocked `stderr=""` and would now
correctly fail the new check.

### Fixed stale version display after repeated updates (real bug, user-caught)
User noticed the terminal banner on a real scan (in ~/repos/dtap) still said
v0.7.4 despite ~10 version bumps earlier this session. Root cause: `./install`
only runs `pip install -e .[report]` when `import rich, vaptkit.menu` fails -
true only on a genuinely fresh venv. Once that import succeeds, the script
never reinstalls again on later runs. An editable install keeps running live
code from disk (so behavior updates every `git pull`, no bug there), but its
recorded version/dependency metadata is a snapshot frozen at whatever it was
on the LAST actual `pip install -e .` - confirmed the actual installed dist
said 0.7.4 while pyproject.toml said 0.8.4. Worse than cosmetic: if a future
version bump ever adds a genuinely new dependency, this same gap means an
existing install would silently never get it, and whatever feature needs it
would crash with `ModuleNotFoundError` until someone manually reinstalled.

Fixed in both `install` and `install.ps1`: once the toolkit is already
installed, compare `pyproject.toml`'s version against
`importlib.metadata.version("matt-vapt-kit")` and only reinstall when they
differ - cheap (two quick reads, no pip call) on the common "already
current" path, and self-heals automatically on every future version bump
without adding pip overhead to every single launch.

Verified against a real reproduction, not just code review: manually rolled
back the project's own `matt_vapt_kit.egg-info/PKG-INFO` version to 0.7.4
(confirmed this, not the venv's `.dist-info`, is what
`importlib.metadata.version()` actually reads for an editable install -
learned this the first attempt, when editing the venv-side dist-info instead
did nothing), then ran the real `./install` end to end: it printed
"Updating the toolkit to v0.8.4...", reinstalled, and
`importlib.metadata.version()` came back correct immediately after. Ran it a
second time afterward to confirm the no-op path doesn't trigger a redundant
reinstall once versions match.

`install.ps1` got the same fix mechanically translated (not run on a real
Windows machine - same pre-existing, already-documented verification gap as
the rest of the Windows path).

### Bounded same-origin crawler (closes the last NCERT-toolset gap: Burp's spider)
Asked the user directly what else from the real NCERT/CERT-PH toolset
(Dirsearch, Feroxbuster, Burp Suite, Subfinder, Nslookup, Nmap, Wappalyzer)
wasn't covered yet. Everything was, except one piece of Burp's role:
crawling/spidering to discover pages beyond the homepage. The kit only ever
fetched `/` once and looked at `<script>` tags on it - it had no way to find
`/dashboard` or `/api/docs` linked from the homepage but absent from
robots.txt, sitemap.xml, and the fixed exposure path list.

`recon.py::extract_same_origin_links(host, body)` (pure, no network):
parses `<a href>` from an HTML body already in hand, keeps only relative
paths and absolute URLs matching `host` exactly, explicitly excludes
protocol-relative `//evil.invalid/x` links (same-looking but a different
host), `mailto:`/`tel:`/`javascript:`/`data:` schemes, fragment-only and
homepage-only links; strips query/fragment, dedupes, caps at 25 candidates.
Deliberately shallow - homepage links only, not a multi-page crawl, matching
the kit's existing "no extra requests beyond what's already being fetched"
bias for passive checks.

`exposure.py::run()` gained an `on_links` callback (same shape as the
existing `on_homepage` one): takes the candidate list, confirms reachability
with a lenient HEAD per candidate (same bypass-`call()`/no-`stop_on_http`
convention as the open-redirect probe - a 404 or blocked link is "nothing
found," not a reason to abort the whole exposure scan), respects
`excluded_prefixes`, and only calls back with links that actually returned
2xx. `assessment.py` wires this into `recon["discovered_paths"]` alongside
the existing robots.txt/sitemap.xml entries - no schema change needed, same
field, same cap.

11 new tests: `test_recon.py` (7, pure `extract_same_origin_links` cases -
same-host absolute vs relative, different-host and protocol-relative
exclusion, non-http schemes, fragment/homepage exclusion, dedup, the 25-item
cap) and `test_exposure.py` (3, through `run()` - only reachable links
reach the callback, excluded prefixes are respected, no HTML homepage means
no callback at all). Smoke-tested end to end against a stub combining every
case at once (an internal 401 route, a dead link never actually linked
successfully, an external phishing-style link, a mailto link): only the one
genuinely reachable same-origin page came back.

### JWT weakness check (last item from the original "what else can we add" list)
Only relevant for projects using `role_testing.login.session.type: bearer`
(PEMEDES-shaped; DTAP uses cookies). New `vaptkit/jwt_check.py`: pure,
no-network, no-signature-verification decode of a bearer token's header and
payload (base64url + JSON), flagging three things regardless of what the
signature says: `alg: none` (or missing `alg`) - critical, the token isn't
cryptographically signed; missing `exp` claim - high, never expires; and an
`exp - iat` over 30 days - medium, unusually long-lived. An opaque
(non-3-segment) token or one that doesn't decode to JSON objects returns no
weaknesses - the check only applies when the token is actually a JWT, no
false positives on opaque session tokens.

Explicitly out of scope, documented in the module docstring: this does NOT
forge a token (e.g. flip a real token's `alg` to `none` and strip the
signature) and resend it to see whether the server's verifier would accept
the bypass - that's a separate, active authentication-bypass test against a
real protected route, with its own approval/risk profile, not attempted
here. This check only reports what the issuer actually put in a token it
already issued during normal role testing.

Wired into `roles.py::run()`: checked once per account right after
`sign_in()` establishes a bearer session (before `session.clear()` removes
the token), deduplicated by weakness code across accounts so a systemic
issuer misconfiguration is reported once, not once per test account.
Findings use `category: configuration`, `owasp: A07` (Authentication
Failures - already a valid schema value, no schema change needed).

17 new tests: `test_jwt_check.py` (16, pure unit tests covering decode
failures, non-JWT tokens, each weakness individually, and the "well-formed
short-lived token has no weaknesses" negative case) plus one real
integration test in `test_roles_bearer_login.py` building an actual
`alg: none`/no-`exp` JWT through the full bearer-login flow, confirming
both weaknesses are flagged exactly once (not duplicated across the two
test accounts) and the token's signature value never appears in the
written result file. Also manually confirmed the PDF path renders a JWT
finding correctly (apostrophe in the title HTML-escapes as expected, not a
bug) and that `certph.py`'s OWASP label dict already covers A07.
(`.venv/bin/python -m unittest discover -s tests`); 15/15 semgrep rule tests
pass (`docker run ... semgrep --test --config=/rules /src/tests/semgrep`).

### Leftover console.log / emoji-debug static rules
User asked directly: is there something that checks for hardcoded
console.logs and things like emoji that shouldn't be in production code?
Yes - this is exactly what the kit's existing semgrep layer is for
(it already flags `eval`, disabled TLS verification, and shell injection
via template strings the same way). Two new rules in
`vaptkit/rules/javascript.yml`:

- `console-log-statement`: flags `console.log`/`console.debug`/
  `console.info` anywhere in JS/TS source. Deliberately does NOT flag
  `console.error`/`console.warn` - those are commonly intentional
  production error reporting, and flagging them would make the rule too
  noisy to trust.
- `console-emoji-debug`: flags ANY `console.*` call (including error/warn)
  whose message argument contains an emoji character, via
  `metavariable-pattern` + a unicode `pattern-regex`
  (`\x{1F300}-\x{1FAFF}`/`\x{2600}-\x{27BF}`/`\x{2190}-\x{21FF}`) - an emoji
  in a log line is a near-certain sign of leftover ad-hoc debugging
  (`console.log("🚀 starting")`) regardless of which console method carries
  it, so this one deliberately overrides the error/warn exemption above.

Explicitly asked the user first whether this should block pushes (like the
existing 3 JS rules do, since semgrep's `--error` flag in `scan_static()`
fails on ANY rule match regardless of declared severity - there is no
severity-based filtering in this kit today) or just show up as a
non-blocking report finding; answer was block, same as the existing rules,
so no new plumbing was needed in `checks.py`.

Verified against the real pinned semgrep image, not just written and
assumed correct: a scratch fixture with `console.log`/`debug`/`info`/
`error`/`warn` (plain and with emoji) plus a `pino` structured-logger call
confirmed every expected line matched, including both rules firing on the
one line that should trigger both (`console.log("🚀 ...")`). Hit a real
`semgrep --test` syntax gotcha while writing the fixture: stacking two
separate `// ruleid: X` / `// ruleid: Y` comment lines above the same code
line does NOT associate both rule IDs with that line the way it looks like
it should - semgrep's test parser needs the comma form,
`// ruleid: console-log-statement,console-emoji-debug`, on one line.
Worth remembering for any future rule whose test fixture needs a line that
two rules are expected to both match.

Also confirmed `vapt check . --static` still exits 0 against this repo's
own committed tree after adding the rules (the repo is Python; the only
tracked `.js` file is the semgrep test fixture itself, already excluded via
`.semgrepignore`), and that `semgrep --test` (what CI's "Test local Semgrep
rules" step runs) passes 15/15 after fixing the annotation gotcha above.

### Dependency-audit waiver (osv-scanner.toml) - unrelated to the recon work below
Came from a different concurrent session working on DTAP's push: that AI flagged
a real asymmetry rather than just agreeing to `--no-verify` a push blocked by a
node-forge RSA-signature-forgery advisory with no upstream fix yet (used by
`lib/pnpki/verify-signature.ts`). Secrets have a reviewed, committed waiver
(`.gitleaksignore`); the dependency audit had none, so a team hits a genuine,
accepted, un-fixable advisory and is stuck choosing between `--no-verify`
(bypasses everything, not just that one advisory) or never touching the
lockfile again until upstream ships a fix.

Fixed in `checks.py::audit_commit()`: if the commit being checked has a
committed `osv-scanner.toml` at its root, it's copied into the scan's temp
directory (same `git show {sha}:...` pattern as `.gitleaksignore`, same
"missing is fine" `except ToolError` handling) and passed to osv-scanner via
`--config /src/osv-scanner.toml`. Deliberately uses osv-scanner's own native
`[[IgnoredVulns]]` waiver format instead of inventing a custom one - nothing
in this kit has to parse or trust it, osv-scanner does.

Verified against the real pinned osv-scanner image (not mocked) before
trusting this, since the docs were ambiguous about auto-detection: confirmed
`osv-scanner.toml` sitting in the scan root is NOT picked up automatically -
the `--config` flag is required, or the waived advisory still blocks. Ran a
real audit_commit() end to end against a throwaway repo with a known
minimatch CVE: 4 vulnerabilities without the waiver, 3 with it (the exact
waived GHSA-ID gone, the other 3 unrelated minimatch advisories unaffected).
2 new tests in `test_checks.py` (`test_committed_osv_scanner_toml_is_passed_as_config`,
`test_no_osv_scanner_toml_omits_config_flag`).

Not documented anywhere user-facing yet - checked, and `.gitleaksignore`
itself isn't documented in README/docs either, so this isn't a new gap,
just an existing one. Worth a docs pass for both waiver mechanisms together
if a teammate asks how to use either.

### Open redirect check
Last pick from the original "what else can we add" list. Probes 8 common
redirect-param names (`next`, `redirect`, `redirect_uri`, `return`,
`returnUrl`, `url`, `continue`, `dest`) on `/` with a random, never-before-
seen external marker URL (`https://mvk-redirect-<16 hex>.invalid/`) as the
value, right alongside the existing homepage fetch and CORS probe in
`exposure.py::run()`. Flags only when a response is a real 3xx AND the
Location header contains that exact marker - an unambiguous signal, not a
guess, since no real external site was ever contacted and the marker can't
pre-exist anywhere.

Deliberately bypasses `call()`/`stop_on_http` for these specific probes
(calls `request`/`pause` directly instead): a 3xx is the signal being
looked for, not a reason to abort the rest of the exposure scan, and any
other status from a guessed query parameter the app may not even read
(401/403/429/5xx included) is "nothing found," the same convention as every
other best-effort probe in recon.py. Transport errors (`OSError`,
`TimeoutError`) are caught per-param and just move to the next one.

New `open_redirect` exposure kind (medium severity), IMPACT/REMEDIATION
entries, schema enum, and `report.py`'s PDF label dict updated (the same
dict whose missing-key crash the CORS work fixed earlier this session -
caught immediately this time instead of needing a second bug hunt).
Verified end to end against a real stub server simulating a vulnerable
echo-redirect endpoint, not just mocks. 5 new tests in `test_exposure.py`
(flagged when marker echoed back in a 3xx Location; not flagged for an
unrelated redirect target, a non-3xx response, or a network failure) plus
1 regression test in `test_report.py` for the new kind's PDF label.

### DKIM selector discovery (completes SPF/DMARC email-hygiene triage)
`recon.py::dkim_selectors_found(domain)` checks a fixed list of 11 common
DKIM selector names (`google`, `selector1`/`selector2` for Microsoft 365,
`k1`/`k2` for Mailchimp/common ESPs, `default`, etc.) and reports which ones
publish a `v=DKIM1` TXT record, reusing the exact same `dns_txt()` plumbing
as SPF/DMARC -- zero new network primitives, passive, off-target, no
approval needed, same as the rest of `dns_hygiene()`.

Explicitly NOT a presence/absence signal the way SPF/DMARC are: the real
DKIM selector is chosen by whatever mail provider is in use and is not
discoverable without seeing a real signed email's `DKIM-Signature` header,
so an empty result only means "none of these 11 common names," never
"DKIM is unconfigured." Documented inline and in the docstring so nobody
mistakes this for a confirmed finding later.

Wired into `dns_hygiene()`'s return value (`dkim_selectors_found` field),
schema updated, `live.py` recap calls it out only when something is found
(a positive signal is worth surfacing; a negative one here is not
meaningful, unlike the existing "no DMARC record" note). Smoke-tested
against real domains: airbnb.com/stripe.com -> `google`, github.com ->
`selector1`, `google`, `k2`; google.com/notion.so/slack.com -> none of the
11, as expected since they use rotating or less common selectors not on
this list.

3 new tests in `tests/test_recon.py` (`DkimSelectorsFoundTests`: no match,
matching selector, TXT record present but not DKIM-shaped is ignored);
`DnsHygieneTests`' 2 existing tests updated for the new field.

### CORS misconfiguration check
Next pick from the "what else can we add" list: the classic exploitable CORS
combination, `Access-Control-Allow-Origin` reflecting an arbitrary attacker
origin while `Access-Control-Allow-Credentials: true` is also set (lets any
website read authenticated responses on behalf of a logged-in visitor). A
bare wildcard with no credentials is deliberately NOT flagged -- common and
intentional for public APIs, keeping this as accurate as the rest of the
kit's header grading.

`headers.py::cors_misconfigured(probe_origin, headers)` is the pure decision
function (new tests in `test_headers.py`). `exposure.py::run()` sends one
extra GET to `/` with a random, never-before-seen `Origin` header
(`https://mvk-cors-<16 hex>.invalid`) right alongside the existing homepage
fetch, reusing the same `call()`/scope-exclusion/stop-on-error plumbing as
everything else that touches the target -- no new approval flag needed,
`exposure_checks` already gates it. New `cors` exposure kind added to
`CHECKS`'s IMPACT/REMEDIATION dicts and the report schema's kind enum.

Caught and fixed a real pre-existing bug while wiring this in:
`report.py`'s PDF exposure table builds an `exposure_labels` dict keyed by
kind and does a bare `exposure_labels[item['kind']]` lookup with no
`.get()` -- any new exposure kind not yet known to that dict would
`KeyError` and crash PDF generation. Added `"cors"` there and a dedicated
regression test (`test_cors_exposure_record_renders_without_error` in
`test_report.py`) so a future new exposure kind added to `exposure.py`
without a matching `report.py` label gets caught by tests instead of
discovered at PDF-generation time in the field.

10 new tests total (`test_headers.py`: 5 unit tests for
`cors_misconfigured`; `test_exposure.py`: 4 integration tests through
`run()` -- reflected+credentials flagged, wildcard not flagged, fixed
allowlisted origin with credentials not flagged, non-2xx probe response not
flagged; `test_report.py`: 1 PDF-rendering regression test).

### robots.txt / sitemap.xml path discovery
Checked what else was worth adding beyond the NCERT toolset parity work: HTTP
security headers and cookie-flag checks turned out to already be fully
covered by `headers.py::grade()` (HSTS, CSP, X-Frame-Options, nosniff,
referrer-policy, cookie Secure/HttpOnly) -- no duplicate work needed there.
Favicon/JS-library hash fingerprinting was considered and skipped: it is
only useful against a reference hash database (the way Shodan/FOFA do it),
which this kit has none of and isn't going to maintain, the same reasoning
that ruled out `nmap --script vuln`.

What was actually missing: `vaptkit/recon.py::parse_robots()` /
`parse_sitemap()` (pure, body-in-paths-out, tested without any network) plus
a fetch in `assess()` (`vaptkit/assessment.py`) for `/robots.txt` and
`/sitemap.xml` via the existing `recorded_request`, gated the same as
`scan_ports`/`tls_hygiene` (only once earlier stages are clean, still
excluded-prefix-checked) since it touches the target. A missing file,
redirect or any transport error is treated as "nothing found", not an
assessment failure, matching the rest of recon.py's convention. Result
surfaces as `recon["discovered_paths"]` (schema updated, capped at 100
entries), called out in `live.py`'s recap. These are discovered candidate
paths for follow-up, not findings on their own -- a site publishing
robots.txt/sitemap.xml on purpose is normal, not a vulnerability.

Smoke-tested against a real robots.txt (google.com) end to end. 7 new tests
in `tests/test_recon.py` (parse_robots/parse_sitemap: dedup, wildcard and
blanket-disallow exclusion, empty body).

### TLS/cipher hygiene (closes the last gap in the NCERT/CERT-PH recon parity work)
`vaptkit/recon.py::tls_hygiene()` is the stdlib equivalent of `nmap --script
ssl-enum-ciphers`, without shelling out to nmap (same no-binary-dependency
style as `dns_hygiene()`): pins a handshake to exactly SSLv3/TLSv1.0/TLSv1.1
(`_accepts_protocol()`) to report which legacy protocol versions the server
still accepts, plus the cipher negotiated on a normal connection and days
until certificate expiry (`_days_to_expiry()`). Hostname/cert verification is
deliberately disabled only inside the legacy-protocol probe (not the real
connection) since the point is to isolate protocol negotiation from cert
trust; flagged by the repo's own security-guidance hook and is intentional,
documented inline.

Wired into `assess()` in `vaptkit/assessment.py` as `result["recon"]["tls"]`,
gated behind the same approval/public-address check as `scan_ports` (it
touches the target) and only runs when `target.url` is `https`. Schema
updated (`vaptkit/schemas/report.json`). `live.py`'s `staging_recap()` now
calls out legacy TLS support and certs expiring within 30 days.

`tests/test_recon.py` (8 new tests): `_accepts_protocol`/`_days_to_expiry`
unit tests plus full `tls_hygiene()` tests with mocked sockets (connection
failure -> all-None, not an exception; legacy protocol + cipher + expiry
reported correctly). `tests/test_accuracy_benchmark.py` patches
`vaptkit.recon.tls_hygiene` alongside the other recon mocks so the benchmark
doesn't make a real TLS connection. Smoke-tested against a real host
(www.google.com: no legacy protocols, TLS_AES_256_GCM_SHA384, correct cert
expiry).

### Deliberately not done (unchanged from the Oct 8 session)
- `nmap --script vuln` equivalent — still skipped; broad signature-based CVE
  scanning would mean either shelling out to nmap (breaking the no-binary
  pattern) or reimplementing dozens of CVE checks, for low value given their
  own report found nothing from it.
- Full `-p- -A -sV` depth — still a short common-service port list with a
  plain connect, not a full sweep.

## What this session added (2026-10-08, archived)

Current version: **v0.7.5**. 314 tests pass (`.venv/bin/python -m unittest discover -s tests`).

### 1. Made role/ownership testing universal, not DTAP-specific
The user's explicit instruction mid-session: *"what i want here is anything that
we make, its universal not just for specific repo or project."* `roles.py` and
`ownership.py` previously hardcoded DTAP's login shape (`/api/auth/signin`,
cookie names `auth-token`/`session-bind`, role field `user_type`). Generalized
both to read everything from a new `role_testing.login` config block:
`login_path`, `logout_path`, `identity_path`, `email_field`, `role_field`, and
a `session` block that is either `{type: cookie, cookie_names: [...]}` or
`{type: bearer, token_path: [...], header: ...}`.

- `vaptkit/schemas/project.json`: adapter renamed `dtap-cookie-v1` →
  `session-login-v1`; added the `login` schema block (required).
- `projects/dtap.vapt.yml` migrated to the new shape.
- `tests/test_roles_bearer_login.py` (new): proves genericity against a second,
  differently-shaped real app (PEMEDES: bearer token, `role` not `user_type`,
  different login path) — no cookies ever sent, verified by the test's own
  `assertNoCookieHeader` check.
- Found and fixed a real bug during the refactor: `sign_out()`'s guard changed
  from `if not session` (a plain cookie dict, falsy when empty) to a wrapper
  dict (`{"type": ..., "values"/"token": ...}`) that is always truthy even when
  no session was ever established — so a failed login would still attempt a
  sign-out POST. Added `has_session()` to check the actual payload instead of
  dict truthiness.
- `release_tests/test_role_challenge.py` had its own hardcoded
  `dtap-cookie-v1` fixture that broke CI on this adapter rename. Fixed and
  re-verified; cut **v0.7.5** since v0.7.4 had shipped with this CI red.

### 2. Fixed a real, non-flaky CI failure (not what it looked like at first)
`tests/test_assessment.py::ScopeTests` was failing on every `main`-branch push
since the ownership-checks commit (looked like network flakiness at first
glance, since tag-triggered "Release challenge" runs — a different workflow —
kept passing and masked it). Root cause: `pemedes.vapt.yml` uses
`iap-service-account` access, so `assess()` built request headers via
`ServiceAccountAccess.headers()` — a real `gcloud`/IAM Credentials API call —
as an **eagerly-evaluated argument** to the mocked `observe()`, bypassing the
mock entirely. Fixed by patching `ServiceAccountAccess.headers` in
`ScopeTests.setUp`.

### 3. Fixed a real Rich/terminal rendering bug
The clickable repo/output path in the scan header had its underline (and
hyperlink escape sequence) stretch far past the visible text into the table's
padding. Cause: `path_link()` applied `Style(underline=True, link=...)` as the
`Text` object's **base style**, so `Table`'s cell padding — appended to
`Text.plain` after the fact — inherited it too (confirmed by inspecting the
raw ANSI: `\x1b[4m/path/here                    \x1b[0m`, underline covering
the trailing spaces). Fixed with `text.stylize(style, 0, len(display))` to
scope the style to just the real text.

### 4. Menu UX fixes (from a user screenshot)
- Reworded the `r = reports, f = folders, Enter = skip` prompt (confusing per
  direct user feedback) to spell out what each key does:
  `Press r to open the report, f to open the folder, or Enter to go back`.
- Removed a redundant second "Press Enter to go back to the menu..." prompt
  that always ran immediately after the one above, even though pressing Enter
  there already meant "go back." `offer_open()`/`show_report()`/
  `offer_scan_pdf()` now return whether the caller still needs to show that
  second pause (only true if the user actually opened something, or the
  open-prompt was skipped entirely for that code path).

### 5. Added CERT-PH-equivalent recon coverage
The user asked what tools NCERT/CERT-PH actually use in their DTAP pentest
report (found in `~/Downloads/Ticket#14928_..._DRAFT.pdf`, password-protected —
decrypted with `qpdf`, read, then the decrypted copy was shredded) and asked to
cover everything in it. Their methodology: **Dirsearch**, **Feroxbuster**,
**Burp Suite** (crawling), **Subfinder**, **Nslookup** (DMARC), **Nmap**
(`-p- -A -sV -Pn`, `--script ssl-enum-ciphers`, `--script vuln`), and the
**Wappalyzer** browser extension. No Nessus/Acunetix/Qualys/ZAP/Nuclei.

Added, all gated behind the existing `exposure_checks` approval flag
(unauthenticated targets only), all driven purely from `target.url` — no new
per-project config, keeping the "universal, no extra setup" rule the user set
earlier in the session:
- **`vaptkit/exposure.py`**: expanded the fixed path list from 12 to 34 entries
  (backup/database dumps, cloud/deploy credential files, other VCS metadata,
  common admin panels) — the directory-busting part of their methodology,
  reusing the existing baseline/signature-confirmation machinery so it needed
  no wordlist file or extra setup.
- **`vaptkit/recon.py`** (new):
  - `dns_hygiene()` — SPF/DMARC presence via a **hand-built DNS TXT query**
    over raw UDP sockets (no `dig`/`nslookup` binary dependency, so it works
    the same on a machine that doesn't have one installed).
  - `subdomains()` — passive enumeration via crt.sh certificate-transparency
    logs; never touches the target.
  - `fingerprint()` — tech detection (Next.js/React/WordPress/Express/PHP/
    Apache/nginx) from the homepage response `exposure.run()` already fetches
    for source-map discovery (added an `on_homepage` callback hook to
    `exposure.run()` so this needs no extra request).
  - `scan_ports()` — plain TCP connect scan (no payload) against a ~30-port
    common-service list; the Nmap-equivalent piece, added last after the user
    confirmed they wanted it too. Only runs once the earlier stages complete
    without errors, since unlike DNS/subdomains it does touch the target.
- Wired into `assess()` as `result["recon"]` (schema updated in
  `vaptkit/schemas/report.json`); surfaced in the staging-check recap text in
  `vaptkit/live.py`.
- `tests/test_recon.py` (new, 14 tests): pure-function tests for DNS parsing,
  fingerprinting, and port scanning with mocked sockets; network-failure paths
  (DNS unreachable, crt.sh down/502) assert graceful empty-result handling,
  not exceptions.
- `tests/test_accuracy_benchmark.py`: had to patch `vaptkit.recon.dns_hygiene`
  /`subdomains`/`scan_ports` in `AccuracyBenchmark.setUp` — this test pins
  every socket connection to a local loopback server, and the new recon calls
  would otherwise try to reach real DNS/crt.sh during the test.

### Deliberately not done
- No Nmap-equivalent cipher/vuln scripting (`--script ssl-enum-ciphers`,
  `--script vuln`) — only the port-discovery half of their Nmap usage. Their
  own report found nothing from those scripts anyway (modern TLS, ports
  Cloudflare-fronted); flag to the user if they want this revisited.
  Their own report's other findings (outdated Next.js via Wappalyzer) are
  already covered more thoroughly by the kit's existing dependency-audit
  check against the actual lockfile, not just a runtime version guess.
- `scan_ports()` is a deliberately short, common-service port list, not a full
  `1-65535` sweep like `nmap -p-` — a full sweep would be slow and far more
  intrusive against someone else's infrastructure for a self-assessment tool.

## What this session added (earlier, archived)

- Menu option 3 (was 6), "Compare the last two scans" (`show_compare`, `compare_scans`,
  `scan_findings` in `menu.py`): diffs `static-findings.json` and
  `route-review.json` between the two most recent `.private/scan-*` folders,
  reporting new/resolved static-rule matches and new/resolved no-auth API
  routes. Needs 2+ scans to show anything.
- Readiness check (menu option 6, was 3) now reports whether the Nuclei/ZAP Docker
  images used by local attack testing (option 5) are already pulled
  (`missing_local_attack_images`) and offers to download them up front, so
  the first attack-test run doesn't stall on an image pull mid-scan.
- Tests added in `tests/test_menu.py`; 221 tests pass (`.venv/bin/python -m
  unittest discover -s tests`).
- One-command installers: `./install` (Linux/macOS) and `install.ps1` (Windows
  PowerShell) bootstrap `.venv`, `pip install -e .`, then launch the `vaptkit`
  menu. `./install` was tested end-to-end against a genuine fresh clone (no
  `.venv`): first run installs and launches, second run skips straight to the
  menu. `install.ps1` was written and reasoned through but **not run on an
  actual Windows machine** — no Windows environment was available this
  session. Treat it as unverified until a teammate runs it and reports back.
- Documented a real Windows gap: menu option 5 (local attack testing) uses
  `docker run --network host`, which Docker Desktop on Windows does not
  support the way Linux does, so it's expected to fail there even if install
  succeeds. WSL is the suggested path for full parity. Noted in README,
  getting-started, and a new "Platform status" section in pilot-checklist.md,
  which also asks for the first Windows `install.ps1` run to be reported back
  before relying on it for other teammates.

- README rewritten for the install scripts and all six menu options, with SVG
  screenshots in `docs/screenshots/` rendered from the real menu code using
  synthetic scan data (generator script was a throwaway in /tmp, not committed).
- Weekly scan: `.github/workflows/weekly-scan.yml` in THIS repo scans
  mattxslv/dtap, pemedes and startup-ph (`main`) every Monday 00:00 UTC.
  Deliberately not placed in the app repos: pushing to their `main` triggers
  production deploys (startup-ph `deploy-production.yml`, DTAP/PEMEDES Cloud
  Build). Needs the `SCAN_REPOS_TOKEN` secret (fine-grained PAT, Contents
  read-only on the 3 repos); the user creates it, it can't be made via gh.
- New finding from a local dry run: **startup-ph has 29 possible secrets in its
  git history** (untriaged, like DTAP's 74 and PEMEDES's 2).

- Terminal header is now just the MVK lockup (caption removed). Logo,
  README banner and social preview in `docs/brand/` are drawn from that same
  block art.
- Windows: Docker scan stages skip `--user` (no `os.getuid`) and gitleaks uses a
  standalone bare clone mounted at `/scan`; option 5 targets
  `host.docker.internal` instead of `--network host`. Exercised on Linux only;
  this laptop's ufw blocks container-to-host traffic, so option 5's Windows
  network path is untested end to end.
- Push protection (menu option 7, and offered automatically on first
  `./install`/`install.ps1`): discovers Git repos under the home folder
  (`find_repos`, depth 4, skips hidden/node_modules), multi-select or `a` for
  all, installs the existing per-repo pre-push hook. The hook now checks only the
  commits being pushed (`remote..local`, or `local --not --remotes` for new refs,
  using a `--mirror` clone so remote refs resolve), blocks on new leaks
  (gitleaks `--exit-code=42`) or high/critical audit results (only when
  package.json/pnpm-lock.yaml changed in the push), and warns but allows the push
  when a check can't run. Verified end to end in a scratch repo: old pushed leak
  doesn't block, new leak blocks with file/line/commit, new branch scans only its
  commits, missing Docker warns and allows. Windows hook chaining uses sh wrapper
  scripts instead of symlinks; untested on real Windows.

- End-to-end test (fresh GitHub clone, scratch HOME; XDG_STATE_HOME must also
  be pointed at the scratch dir or the test writes to the real recent list).
  Passed: install + protect prompt, options 1/2/3/5/6/7, real pushes (clean,
  leak, vulnerable dep, wrong pnpm via corepack, Docker missing), hook
  uninstall. Fixed during it: Docker-missing aborted the dependency audit too;
  ZAP never finished (DOM XSS rule 40026 needs Firefox, which doesn't fit the
  2 GB cap; now disabled via zap-rules.conf); ZAP alert count included the
  totals line. Not tested: option 4 (user chose to skip a live site), weekly
  workflow (no SCAN_REPOS_TOKEN yet), anything on real Windows.
- Option 5 Nuclei is confined to the chosen port: `-pt http` plus an exclude
  list built in-container from templates matching `{{Host|Hostname|BaseURL|
  RootURL}}:<port>` (NUCLEI_SCRIPT in menu.py). Verified with decoy listeners on
  4040/9780: 0 requests to them, 10,811 to the target, 6,901 templates run.

- PDF reports: new `vaptkit/scan_report.py` renders repo scans (same CSS/cover
  as the staging report; no source snippets). Offered after options 1 and 4,
  `p` in option 2, `vapt scan --pdf` (used by the weekly workflow, which now
  installs `.[report]` + Chromium). summary.json now stores project, facts and
  recap. Installers add `.[report]` and download Chromium (~150 MB) if it can't
  launch; existing installs get it on their next run without the protect
  prompt. Tested from a fresh clone with scratch HOME/XDG_CACHE_HOME/
  XDG_STATE_HOME (this shell's XDG vars point at the real user dirs).

- Design pass: loading view shows a shimmer word + real 4-step track (fake
  code lines removed). Main menu grouped (Scan / Live checks / Setup) with
  hints and a status line, left-aligned (`MENU`, `print_menu`, `status_line` in menu.py);
  logo untouched. Repo-scan PDF redesigned: `assets/scan-report.css`, dark cover
  with inline block-art logo (`vaptkit/brand.py`), "What to do first" list,
  rules grouped with their yml messages, running header/footer via CSS
  `@page` margin boxes (Playwright header/footer templates printed over the
  cover). The staging report (report.py/report.css) was not restyled.

- Logo is now the MVK wordmark only: the shield was removed everywhere at the
  user's request (terminal header, PDF cover, docs/brand logo/banner/social
  preview, README screenshots). `SHIELD` is gone; `wordmark_lines()` in scan.py
  is the single source and `vaptkit/brand.py` draws it as SVG. PDF cover centres
  it. Watermark text is just "MATT VAPT KIT" in both reports, positioned in mm
  because Chromium sizes fixed elements to the margin-less cover page.
- Terminal: every former yellow (REVIEW, MISSING, warnings, "need attention")
  is the logo orange `ACCENT` (#d68b68), per the user.

- Live staging without per-run setup: `projects/<name>.standing-approval.yml`
  (approved_by, expires_on) turns on a 5th scan stage, "Live staging
  (read-only)" (`vaptkit/live.py`), which builds a fresh one-hour, HEAD-only,
  exposure-check approval each run; the 4-hour/digest rules are unchanged. User
  ruled out anything needing setup (accounts, IAP, URLs), so only DTAP has one
  (approved_by mattxslv, until 2027-01-08). As of 2026-10-08
  test.dtap.dict.gov.ph does not resolve in DNS; the stage reports it as not
  covered. Do not repoint it at production without the owner's say-so.

- Dependency audit now OSV-Scanner (pinned digest in checks.py `OSV_SCANNER`) over
  committed lockfiles of any common ecosystem (`LOCKFILES`), replacing the pnpm-only
  audit and its "exact pnpm version installed" requirement. Other teams use Node
  (npm/yarn/pnpm) and PHP/Laravel per the user. `audit_commit` returns a report
  (counts by CVSS band, top entries) instead of raising; scan/check/hook decide.
  Evidence: `dependency-audit.json`; PDF has a "Vulnerable dependencies" chapter;
  chapters are auto-numbered. Verified on real pnpm (DTAP: 15, matching pnpm
  audit), composer and npm projects, and a blocked composer.lock push. pnpm/Node
  setup removed from action.yml and the weekly workflow.
- PHP/Laravel code rules added (`vaptkit/rules/php.yml`, fixture
  `tests/semgrep/php.php`, run by CI's `semgrep --test`): raw SQL with variables,
  shell with variables, client filename on upload, hardcoded secrets (value must
  contain a digit, skips lang/tests), debug => true. Blade templates excluded
  (unparseable as PHP). Tuned against laravel/laravel (0) and BookStack (43 -> 6,
  all real raw-SQL review items). Route review is still Next.js-only.
- C#/ASP.NET (user's intranet + HRMIS teams): NuGet added to the audit
  (`.csproj` by suffix, packages.config, packages.lock.json); rules in
  `rules/csharp.yml` (SQL from strings, Process.Start, upload filename, secrets and
  connection-string passwords via pattern-regex because Semgrep's C# matcher doesn't
  bind property assignments, UseDeveloperExceptionPage outside IsDevelopment),
  `rules/aspnet-config.yml` (web.config debug, customErrors Off, validateRequest
  false, connectionString passwords), `rules/aspnet-settings.yml` (appsettings*.json).
  JS rules now skip bundled libs. Semgrep --timeout=30. Tuned on nopCommerce and
  dotnet/eShop. Fixture fakes carry `gitleaks:allow` so the repo's own push
  protection doesn't block them (it did, correctly, on the first try).

- ASP.NET login-check review (`vaptkit/aspnet_routes.py`, called from
  `routes.review`, same route-review.json shape): controllers incl. inherited and
  custom *Authorize* attributes, in-body checks, global filters/fallback policy,
  minimal APIs incl. groups and lambda attributes. Tuned on nopCommerce (620/620
  admin actions protected), eShop, eShopOnWeb. Real finding seen while tuning:
  nopCommerce Brevo plugin `ImportContacts` has no auth at all. User asked NOT to
  build the Laravel route review ("they don't use it here") and then had the PHP
  code rules removed (rules/php.yml, tests/semgrep/php.php). Composer lockfiles are
  still read by the generic OSV dependency audit.

- Released v0.6.0 (first tagged release), then v0.6.1 (version shown under the logo; README pins v0.6.1). README install pins
  `--branch v0.6.0`. Recommended rollout: one Windows teammate pilots first (Windows,
  weekly workflow and the live DTAP stage are still unverified end to end).

- Option 8 "Report a problem" (`vaptkit/support.py`): sanitized diagnostics (home path
  and username hidden) + last recorded error -> pre-filled GitHub issue (label
  `pilot-report`, created on the repo) via the browser, plus a saved copy in
  `.private/`. Menu crashes are caught and recorded; scan tool errors and push-check
  "couldn't run" warnings record too (`record_error`). Released as v0.6.2. Read
  reports with: gh issue list -R mattxslv/matt-vapt-kit --label pilot-report

- Branch scanning (v0.6.3): option 1 fetches (GIT_TERMINAL_PROMPT=0) and offers your
  checkout plus origin/main|master|staging|develop|dev, or all; non-checkout branches
  are scanned by revision (`scan(revision=...)`, `vapt scan --revision`), live stage
  runs once per run. First real run on DTAP (2026-10-08): main and staging diverged
  7 months ago (staging +563 commits, main +20 hotfixes); main has 98 dependency vulns
  (2 critical, 62 high) vs staging 15, and 28 vs 15 suspected unauthenticated
  handlers. The earlier lead-evaluator/requirements auth finding is RESOLVED: the
  route is gone from both branches.

- Option 0 "Full scan of a project" (v0.6.4, `full_scan` in menu.py): all branches, live
  stage once, PDFs automatically, summary table (attention, secrets, high/critical deps,
  no-login handlers, report link). Shares `prepare_project`/`scan_branches` with option 1.
  New "Quick start" group keeps the menu numbered 0-8 top to bottom (test enforces order).

- v0.6.5: multi-branch runs print the logo only once (`scan(header=...)`); after scans,
  `offer_open` asks r = reports / f = folders / Enter = skip (option 0 and single scans).

- v0.6.6: the project picker (options 0/1) lists recent projects first, marked, then
  every other Git repo found under home (`project_list`, reuses `find_repos`).

- v0.7.0 accuracy pass after the first real DTAP triage (another AI reviewed ~140 flags,
  1 real: prod /api/evaluator/profile PUT trusts body userId). Changes: Next.js middleware
  model (routes.middleware_model), ownership check (ID_FROM_REQUEST + WRITES without
  COMPARES_TO_SESSION, admin paths exempt), static matches split runtime vs
  scripts/migrations/tests (is_runtime_path) with PartialParsing as a note, dependency
  runtime/dev scopes (checks.dependency_scopes, report runtime_severity), live stage
  NOT RUN via live.NotCovered when unreachable, DTAP target -> dtap-test run.app behind
  IAP (access iap-browser, remember_login; skipped when no display or CI). Result on
  DTAP: main 1 access-control flag (the real bug), staging 0; code rules 3/2 runtime.
  Role tests now pop `access` from the DTAP config fixture (it opened a real browser).
  Remaining: the 2 example tokens need a .gitleaksignore in the DTAP repo; first IAP
  sign-in must be done by the user from the menu.

- v0.7.1: DTAP and PEMEDES live checks use IAP service-account access through
  dtap-qa-bot@example-project and pemedes-qa-bot@example-project (the user's
  gcloud account holds Token Creator on both; no keys). Both returned HTTP 200 from the
  apps. PEMEDES got a standing approval (until 2027-01-08) and its main config gained the
  review block (public routes, getSessionByToken) that only pemedes-iap had. First live
  result: PEMEDES staging CSP allows unsafe scripts (confirmed); DTAP staging headers
  clean. Ownership check now accepts helper calls like is...Authorized(...). PEMEDES route
  review: 7 public-looking signup/lookup endpoints to confirm. The weekly workflow has no
  gcloud identity, so its live stage reports NOT RUN. Tests that use the real DTAP/PEMEDES
  configs pop `access`. The Chrome seen running was the Playwright MCP plugin, not the kit.

- Two-account ownership checks (`vaptkit/ownership.py`, `vapt ownership`/`vapt scope-template
  --ownership`): config-driven, reuses `roles.sign_in`/`sign_out` (extracted from roles.py's run(),
  behavior-preserved, 284/284 role tests still pass after the extraction). Each check reads the
  target's value, has the acting account overwrite it via the target's id, re-reads as target to
  confirm, restores regardless of outcome -- including restoring the acting account's own record if
  a properly-scoped endpoint wrote there instead (that's how a fixed endpoint is told apart from a
  truly ambiguous accepted-but-nothing-changed result; first version of this flagged fixed endpoints
  as "suspected", caught by its own test suite). DTAP config now has one real check,
  evaluator-profile-department, targeting the exact live bug (evaluator vs evaluator-2, PUT
  /api/evaluator/profile, id_field userId). Schema updated (project.json) for `ownership_checks`.
  Tested only against a mocked HTTP app simulating the real vulnerable and fixed route code (5 new
  tests, all pass) -- NOT run against real DTAP/PEMEDES staging. That needs the DTAP_EVALUATOR_EMAIL
  /DTAP_EVALUATOR2_EMAIL/DTAP_QA_PASSWORD values and the user's explicit go-ahead, since it performs
  real (reversible) writes under the evaluator accounts. CLI-only, like `vapt roles`; not added to
  the menu given the password-prompt/approval flow doesn't fit the current menu UI.

- Second round of pilot feedback (#3, #5, #6, #7, #8 from the peer session's list; #1/2/4 from
  that same list were already shipped earlier this session -- confirmed by checking git log, told
  the peer session via SendMessage to pull latest):
  - #3 (symmetric HTTP-method coverage): already true in code (routes.py's METHODS tuple and
    aspnet_routes.py's HTTP_VERBS/MAP_VERBS cover GET/POST/PUT/PATCH/DELETE identically; confirmed
    against real DTAP main -- all 5 methods analyzed and authenticated at the same rate). Added a
    regression test (test_routes_middleware.py) locking this in, since it was previously unverified
    by any test.
  - #5 (lead with reachable count): dependency messages in both scan.py and checks.py now say
    "N high/critical in runtime dependencies" first, "(of M total across P packages)" second,
    instead of the raw total leading. recap() and the push-hook message updated to match. Verified
    against real DTAP main: "28 high/critical in runtime dependencies, update those first. 98 known
    vulnerabilities...".
  - #6 (CI gate): `vapt check` / action.yml gained `--routes` (default true in the action), which
    runs the offline route review using the matching projects/*.vapt.yml (matched by repo folder
    name, same lookup as the menu's project picker) and fails the check if any access-control
    finding exists. NOT wired to live regression checks -- those need IAP credentials the push
    workflow doesn't have; flagged as a real limitation, not attempted. Also fixed a bug this
    surfaced: `vapt check`'s secret-history step still used the old blunt scan_history (raw exit
    code, no placeholder detection) while scan() had already been fixed; both now go through
    history_findings with the same placeholder-aware logic.
  - #7 (fix diffs): largely already covered by drift.py (built earlier this session), which links
    the fixing commit per finding. Added a top-level "method" field to routes.py's finding() dict
    (was previously only embedded in the impact text) and surfaced it in drift.py's route entries
    and the PDF's ownership-finding table.
  - #8 (CERT-PH export): new `vaptkit/certph.py` / `vapt export-tickets` / menu option 2 -> `t`.
    One ticket per finding (route review, runtime static matches grouped by rule, runtime
    high/critical dependencies grouped by package+version, non-placeholder secrets), most severe
    first, rendered as a Markdown table. Explicitly labelled best-effort -- this kit has not seen an
    actual CERT-PH/DC-003 template, so the field names are a guess at a typical layout, not a
    verified match. Verified against a real DTAP main scan (15 tickets, correctly sorted, grouped
    lodash/minimatch/etc. advisories).
  - Hit and fixed a real file-overwrite race while editing menu.py with back-to-back python3
    heredocs in one Bash call: the second heredoc's `p.read_text()` didn't see the first heredoc's
    write (tool's own "modified on disk since you last read it" notice caught it on the Edit-tool
    retry). Re-applied via the Edit tool and confirmed with grep before moving on. Worth remembering
    if a future multi-step python-heredoc edit to the same file in one Bash call silently reverts.

- Generalized role/ownership testing (user: "i want this to be universal not just for a
  specific repo or project"). roles.py/ownership.py were hardcoded to one login shape:
  fixed LOGIN="/api/auth/signin"/LOGOUT paths, fixed COOKIE_NAMES, hardcoded identity
  fields "user"/"email"/"user_type". New adapter session-login-v1 reads all of this from
  role_testing.login in the project config: login_path, logout_path, identity_path,
  email_field, role_field, and session (type: cookie + cookie_names, or type: bearer +
  token_path + header). dtap.vapt.yml migrated to it (schema updated, same runtime
  behavior -- all 298 existing tests pass unchanged after the migration). Proved
  genericity against a SECOND real, differently-shaped app rather than just renaming
  constants: verified PEMEDES's actual signin route and auth.ts
  (app/api/auth/cloudsql/signin/route.ts -- different path, {user, session.access_token}
  response, no Set-Cookie at all, role field named "role" not "user_type") and wrote
  tests/test_roles_bearer_login.py, a complete bearer-token config shaped exactly like
  it, which passes through the identical roles.py code with zero DTAP-specific branches.
  Caught and fixed a real bug along the way: sign_out()'s "was a session ever
  established" check used to be `if not session` on a plain cookie dict (empty dict is
  falsy); once session became a wrapped {"type":..., "values"/"token":...} dict for the
  bearer case, that wrapper is always truthy even with no actual token, so a failed
  bearer login would have still attempted a sign-out call. Added has_session() to check
  the payload, not just the wrapper; two existing DTAP tests
  (test_login_denial_is_not_retried, test_iap_redirect_or_denial_is_not_a_passing_matrix)
  caught this immediately. NOT done: a real pemedes.vapt.yml role_testing/ownership_checks
  section -- deliberately did not invent PEMEDES's exact account IDs or full identity
  JSON nesting beyond what was directly verified in its code; wiring that for real needs
  someone to confirm it against an actual PEMEDES login response first. Also deliberately
  out of scope: SSO/OAuth2/MFA login flows -- the adapter only covers direct JSON
  credential POST -> cookie-or-bearer session, by design (safety/complexity), documented
  in docs/reference.md.

Previous handoff (2026-10-07 menu/redesign work, DTAP finding) preserved below.

Replaces the Oct 5 handoff below this line's content; that session's "pending" items
(exposure checks, role testing, accuracy benchmark, v0.5.0 release) are all in `main`.

## What this session added (commits ahead of the previous push)

1. **Numbered terminal menu** — run `vaptkit` for a menu instead of raw CLI flags.
   Entry point in `pyproject.toml` (`vaptkit = "vaptkit.menu:main"`), code in
   `vaptkit/menu.py`. Options:
   1. Scan a project (recent folders remembered in
      `~/.local/state/matt-vapt-kit/recent-projects.json`; project YAML auto-matched
      by folder name, e.g. `~/DTAP` → `projects/dtap.vapt.yml`)
   2. See the latest scan results
   3. Check this computer is ready to scan
   4. Quick staging check — paste a URL, confirm permission, the menu builds a
      short-lived project config + approval automatically and runs the existing
      `vapt run` header/cookie/exposure checks (`staging_config()`,
      `staging_recap()` in `menu.py`). PEMEDES (behind Google IAP) is intentionally
      not supported here — public staging URLs only.
   5. Local attack testing — Nuclei + ZAP active scan via Docker, `localhost`/
      `127.0.0.1` only (enforced by `is_local_target()`), `--network host`.
      Capped at `--memory=1g`/`2g` and 10/15 minute timeouts (`NUCLEI_TIMEOUT_SECONDS`,
      `ZAP_TIMEOUT_SECONDS` in `menu.py`); a named container is `docker kill`ed on
      timeout instead of needing a manual Ctrl+C. Warns if `/proc/meminfo` shows
      under 4096 MiB available (`available_memory_mb()`) before starting — this is
      what made a real test run crawl (swap maxed out) earlier in the session.
   - Invalid input in options 4/5 retries in place (`retry_input()` in `menu.py`)
     instead of bouncing back to the menu; type `b`/`back` to cancel.

2. **Terminal visual redesign** (`vaptkit/scan.py`, shared by `menu.py`):
   - Logo: hand-drawn `SHIELD` ASCII icon to the left of an `ansi_shadow`-font "MVK"
     wordmark (`print_header()`), both in the orange `ACCENT` color. No bordered
     panel anymore, no "COMMITTED-CODE CHECKS" subtitle. "Matt VAPT Kit" / "anti
     vince vulnerability" / "to prevent spilling the beans :D" are one centered
     block under the logo.
   - Orange (`ACCENT = "#d68b68"`) is now reserved for the logo and the loading
     spinner only — menu prompts, option keys, stage rule headers, table borders
     and path links all switched to plain/bold/dim, matching how Claude Code's own
     UI reserves orange for its loading indicator.
   - Loading view (`LoadingMessage` in `scan.py`) now shows 3 lines cycling through
     a fixed pool of fake, generic code snippets (`DECOR_CODE_LINES`) behind the
     orange spinner, purely decorative. **Does not** change the kit's existing
     no-real-snippets rule — `static_summary()` still withholds actual matched
     source lines; this was a deliberate user decision after I flagged the
     conflict (see transcript).
   - Finish line format: `✻ Cooked for 2m 5s · done 3:46 PM · 0 completed · 4 need
     attention`, followed by a deterministic `※ recap:` plain-English summary
     (`recap()` in `scan.py`) that prioritizes: leaked secrets > high-severity deps
     > suspected API auth routes > static matches.

3. **Tests**: `tests/test_menu.py` is new (pure-function tests for the menu: config
   generation, local-target validation, recap text, retry loop, memory check,
   stream() timeout behavior). `tests/test_scan.py` updated for the new header
   layout and loading-message shape. 214 tests pass as of the last commit
   (`.venv/bin/python -m unittest discover -s tests`).

## Known real findings surfaced this session (not yet resolved)

- **DTAP: `GET /api/lead-evaluator/requirements` has no auth.** The real check is
  written but wrapped in a `/* ... */` comment with `// TODO: Uncomment this for
  production`, introduced in commit `d47127dd` (2026-01-26). Confirmed still
  present on `main`, `mattxslv/main`, `mattxslv/staging` (the branch serving
  `test.dtap.dict.gov.ph`), and `develop` as of this session. Later security
  cleanup commits (`63e04245`/`f37e32fa`, `483dc46e`, `0b660ad5`) never touched
  this file. **Not fixed yet** — the user asked for a copy-pasteable writeup to
  take to another AI session handling the DTAP incident; I don't know the outcome
  of that session.
- **74 leaked secrets in DTAP's git history, 2 in PEMEDES's** (per the Oct 5
  handoff) — still untriaged as far as I know.
- No `v0.5.0` git tag exists despite the release commit language in the log.

## Safety/behavior notes for whoever continues this

- Local attack testing (menu option 5) actively attacks whatever URL you give it —
  it refuses non-localhost targets, but don't assume that's the only safety rail;
  it still sends real SQLi/XSS-style payloads to a real running process.
- Quick staging check (option 4) requires explicit `y` confirmation before sending
  any request; it still won't do anything against login-protected targets.
- `.private/` (evidence output) and `~/.local/state/matt-vapt-kit/` (recent
  projects) are both gitignored/outside the repo; nothing scan-related leaked into
  git history from this session as far as I checked.

## Running tests

```bash
.venv/bin/python -m unittest discover -s tests
```

## Constraints (unchanged from before)

- No em dashes in repo docs. No AI co-author trailer in commits — wait, this
  session's commits DO have `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`
  per the harness's attribution instructions for this session, overriding the
  older "no AI trailer" note from the Oct 5 handoff. Flag this to the user if it
  matters for a public/private repo policy decision.
- Commit after completing work; push only when explicitly asked (this session's
  13 commits were pushed to `origin/main` only after an explicit "push to
  staging" request — there is no `staging` branch in this repo, only `main`).
- Never modify DTAP or PEMEDES source from this toolkit.
