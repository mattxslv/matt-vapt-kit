# Matt VAPT Kit — Handoff

**Date:** 2026-10-08 (session via Claude Code)

## What this session added

- Menu option 6, "Compare the last two scans" (`show_compare`, `compare_scans`,
  `scan_findings` in `menu.py`): diffs `static-findings.json` and
  `route-review.json` between the two most recent `.private/scan-*` folders,
  reporting new/resolved static-rule matches and new/resolved no-auth API
  routes. Needs 2+ scans to show anything.
- Readiness check (menu option 3) now reports whether the Nuclei/ZAP Docker
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
