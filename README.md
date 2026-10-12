<p align="center">
  <img src="docs/brand/banner.svg" alt="Matt VAPT Kit: anti vince vulnerability, to prevent spilling the beans" width="100%">
</p>

<p align="center">
  <a href="https://github.com/mattxslv/matt-vapt-kit/actions/workflows/test.yml"><img src="https://github.com/mattxslv/matt-vapt-kit/actions/workflows/test.yml/badge.svg" alt="Toolkit checks"></a>
  <a href="https://github.com/mattxslv/matt-vapt-kit/actions/workflows/weekly-scan.yml"><img src="https://github.com/mattxslv/matt-vapt-kit/actions/workflows/weekly-scan.yml/badge.svg" alt="Weekly security scan"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-d68b68" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20(beta)-d68b68" alt="Platform: Linux, Windows beta">
  <img src="https://img.shields.io/badge/status-private%20team%20pilot-1f1b19" alt="Status: private team pilot">
</p>

**Security checks for the team's projects, with private evidence and PDF reports.**
Rule-based, no AI service calls. Built to find and fix issues before an external
VAPT.

> [!IMPORTANT]
> **Private, supervised team pilot.** Not a complete VAPT scanner, a certification
> or a CERT-PH report. A clean result means nothing was found in the tested scope,
> not that the application is secure.

## Install

Needs Python 3.11+ on PATH and Docker running. Clone, then run one command:

```bash
git clone https://github.com/mattxslv/matt-vapt-kit.git
cd matt-vapt-kit
./install
```

Pin a specific [release](https://github.com/mattxslv/matt-vapt-kit/releases) with
`git clone --branch vX.Y.Z ...` if you want a fixed version instead of following `main`.
`./install` (and `install.ps1`) check the installed version against `pyproject.toml` on every
run and reinstall automatically when they differ, so pulling an update is enough — no separate
reinstall step needed.

![Linux install](docs/screenshots/01-install-linux.svg)

On Windows (PowerShell), the last line is
`powershell -ExecutionPolicy Bypass -File .\install.ps1` (the bypass applies to that
command only).

![Windows install](docs/screenshots/02-install-windows.svg)

The first run sets everything up (including the PDF tools, a one-time ~150 MB
download), asks which of your Git projects to protect on every push, then opens the
menu. Afterwards, `./install` or `vaptkit` just opens the menu.

> [!WARNING]
> Windows has not completed a teammate pilot yet; its Docker handling was only
> tested on Linux. Option 5 reaches your app as `host.docker.internal`, which some
> dev servers reject (Vite needs `server.allowedHosts: ['host.docker.internal']`).

### Getting updates

Already installed and a newer version landed on `main`? Just pull and run it again — no separate
install step:

```bash
git pull
./install          # or: vaptkit
```

`./install`/`install.ps1` compare the version in `pyproject.toml` against what's actually installed
on every run and reinstall automatically on any mismatch, so this is the only command anyone needs
after a `git pull`, whether the update changed one line or added a new dependency. The menu also
checks once a day whether `origin/main` has moved ahead and prints a notice if so, so you don't
have to remember to check.

## The menu

![vaptkit menu](docs/screenshots/03-menu.svg)

0. **Full scan of a project:** the one-step option. Pick the project and it scans
   every branch (your checkout, `main`, `staging`), runs the read-only staging check
   if the project has a standing approval, makes all the PDFs and ends with one
   summary table across branches.
1. **Scan a project:** secrets in Git history, vulnerable dependencies (Node, PHP,
   .NET, Python and more — each flagged advisory includes its own published fixed
   version and a note when its severity source disagrees with the computed CVSS band),
   code rules (JavaScript/TypeScript, C#/ASP.NET and web.config, including leftover
   `console.log`/debug statements and ones that log a raw request body or credentials),
   and API routes without a login check (Next.js and ASP.NET). You can
   scan your checkout, `main`, `staging` or all of them; other branches are read
   straight from git, so your working folder is never switched. Projects with a standing approval (DTAP)
   also get read-only checks of their staging site — TLS/cipher hygiene, CORS misconfiguration,
   open redirects, SPF/DMARC/DKIM, subdomains, a bounded same-origin crawl of linked pages, and the
   existing header/cookie/exposed-file checks. Ends with an optional PDF report.
2. **Latest results:** the last scan's table; `p` makes a PDF, `t` exports findings as a
   remediation-ticket table (Markdown) — a best-effort mapping to a typical ticket layout, not a
   verified CERT-PH template.

   ![Latest scan results](docs/screenshots/04-latest-results.svg)
3. **Compare last two scans:** what's new and what got fixed.

   ![Compare scans](docs/screenshots/06-compare.svg)
4. **Quick staging check:** paste any staging URL for read-only header, cookie, TLS/cipher,
   CORS, open-redirect, DNS (SPF/DMARC/DKIM) and exposed-file checks, plus a bounded
   same-origin crawl of linked pages. Asks for permission first; login-protected sites
   aren't supported.

   ![Quick staging check](docs/screenshots/07-staging-check.svg)
5. **Local attack testing:** Nuclei and ZAP against an app on your own machine,
   kept to the port you enter. Sends real attack payloads, so use a disposable
   local copy, never staging or production.

   ![Local attack testing](docs/screenshots/08-local-attack.svg)
6. **Check this computer:** Python, Git, Docker and the scanner images.

   ![Readiness check](docs/screenshots/05-ready.svg)
7. **Protect git pushes:** finds your projects and checks only the new commits
   before each `git push`. New leaked secrets, high/critical vulnerable packages, or
   code-rule hits (`eval`, disabled TLS verification, shell injection, leftover
   `console.log`/debug statements) block the push; if the check can't run, it warns
   and lets it through. A committed `osv-scanner.toml` with `[[IgnoredVulns]]` entries
   waives a specific accepted dependency advisory, the same way `.gitleaksignore` waives
   a reviewed secret match. `git push --no-verify` skips it in an emergency.

   ![Protect your git pushes](docs/screenshots/09-protect.svg)
8. **Report a problem:** collects diagnostics (versions, setup, the last error; no
   findings, code or secrets, username hidden), shows them to you, then opens a
   pre-filled GitHub issue for the maintainer and saves a copy. Crashes and failed
   scans point here automatically.

Screenshots use the real menu code with made-up data, never real findings.

## Reading results

| Status | Meaning |
|---|---|
| `DONE` | That check finished; read its detail for limits |
| `REVIEW` | Findings, or a tool error, to look at |
| `NOT RUN` | A coverage gap, not a pass |

Everything is saved privately under `.private/` and never overwritten. Findings are
*suspected* until a person confirms them.

## Automatic checks

- **Weekly scan:** every Monday 08:00 PHT, GitHub Actions scans DTAP, PEMEDES and
  Startup PH from this repo (nothing is committed to the app repos) and uploads a
  PDF for each. Results: **Actions → Weekly security scan**. Needs the
  `SCAN_REPOS_TOKEN` secret, a read-only token for those repos.
- **Live staging:** `projects/<name>.standing-approval.yml` records the owner's
  approval and an expiry date. While it's valid, scans of that project add the
  read-only staging checks with no prompts; each run still gets its own one-hour
  approval. DTAP and PEMEDES staging sit behind IAP and are reached through their
  QA bot service accounts (`dtap-qa-bot`, `pemedes-qa-bot`) using your own gcloud
  login, so this works only for accounts allowed to act as those bots.

## Without the menu

```bash
./scan ~/DTAP                      # same scan, no install needed
vapt scan ~/DTAP --pdf             # with the CLI installed, plus a PDF
vapt scan ~/DTAP --revision origin/main   # another branch, without checking it out
vapt --help                        # every command
```

## More

[Getting started](docs/getting-started.md) ·
[Reference](docs/reference.md) ·
[Team pilot checklist](docs/pilot-checklist.md) ·
[Cloud Armor and XSS labs](docs/cloud-armor-and-xss.md) ·
[Contributing](CONTRIBUTING.md) ·
[Security and evidence handling](SECURITY.md)

Run the toolkit's own tests with `.venv/bin/python -m unittest discover -s tests`.
Keep credentials, reports and approvals out of Git and public channels.
