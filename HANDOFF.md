# Matt VAPT Kit — Handoff

**Date:** 2026-10-08 (session via Claude Code)

## What this session added

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

- Released v0.6.0 (first tagged release; pyproject bumped). README install pins
  `--branch v0.6.0`. Recommended rollout: one Windows teammate pilots first (Windows,
  weekly workflow and the live DTAP stage are still unverified end to end).

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
