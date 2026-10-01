# Getting started

[README](../README.md) | [Reference](reference.md) | [Team pilot](pilot-checklist.md)

Start with a synthetic report. Install additional tools only for the capability
you plan to use. None of the steps in the first-run walkthrough scans a live target.

## Requirements by capability

| Capability | Requirements |
|---|---|
| CLI, offline config validation, HTML reports | Python 3.11+, Git and repository access |
| Local HTTPS tests and release challenge | OpenSSL |
| PDF export and IAP browser login | The `report` extra, Playwright Chromium and browser system libraries |
| Push checks and optional scanner containers | Docker Engine with Compose; exact project pnpm version for Node audits |
| Keyless IAP access | gcloud signed into an approved identity; administrator-provisioned staging permissions |
| Read-only Cloud Armor review | gcloud and approved Cloud Run/Compute metadata read permissions |
| Local XSS browser lab | The `report` extra and Playwright Chromium; no cloud credentials or live target |
| DTAP endpoint-role checks | Owner-approved scope, verified role policy and private QA credentials |

The examples use Linux shell commands. Linux is the CI environment. Native
Windows and other operating systems have not completed a teammate pilot;
do not assume identical credential, permission or browser behavior.

## 1. Install the CLI

Clone the private repository using your own approved GitHub access:

```sh
git clone https://github.com/mattxslv/matt-vapt-kit.git
cd matt-vapt-kit
```

For a team pilot, the maintainer should supply a **reviewed full commit SHA**.
Check out that revision before installing. Do not assume the newest `main` commit
has completed a team pilot.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/vapt --version
.venv/bin/vapt --help
```

The examples use the virtual environment's executables directly, so activating
the environment is optional. No system-wide `sudo pip` install is needed.
The editable install keeps the CLI tied to this checkout; moving it requires
reinstallation, particularly when using Git hooks.

## 2. Try the offline path

```sh
.venv/bin/vapt validate templates/project.example.yml
mkdir -m 700 .private
.venv/bin/vapt report tests/fixtures/assessment.json \
  --reviewed --html-only --output .private/demo-report
```

Expected results:

- Validation reports `configuration: valid` and `scan_authorized: false`.
- `.private/demo-report/report.html` opens locally and says **SYNTHETIC EXAMPLE**.
- No application target is contacted and no cloud or QA credentials are loaded.

`.private/` is ignored by Git. That is not encryption or a substitute for local
file permissions. Use approved storage on an appropriately protected workstation.
On subsequent runs, reuse the private parent but choose a new output directory.

## 3. Add PDF export only if needed

```sh
.venv/bin/python -m pip install -e '.[report]'
.venv/bin/python -m playwright install chromium

.venv/bin/vapt report tests/fixtures/assessment.json \
  --reviewed --output .private/demo-pdf
```

The output contains `report.html`, `report.pdf` and evidence images when observations
are present. Images show sanitized observation cards, not screenshots of a live
application.

Chromium also needs operating-system libraries. On a supported distribution,
Playwright's `install-deps chromium` command installs its dependencies and may
require administrator privileges. Have your workstation administrator approve
system changes. Alternatively, use the offline Docker export path in the
[report reference](reference.md#your-report-with-screenshots).

## 4. Add Docker tools only if needed

```sh
docker compose build kit
docker compose run --rm kit doctor
docker compose run --rm kit validate projects/dtap.vapt.yml
docker compose --profile report build report
```

Build the core image before the report image: the latter extends
`matt-vapt-kit:local`. These are local build tags, not a published release.
Builds download packages; runtime Compose services default to no network access.

`vapt doctor` checks the bundled core-tool list, not every optional dependency.
Missing `nmap` or `whatweb` on your host does not prevent offline HTML reporting.
Use the local CLI for Git/Docker orchestration; the core container intentionally
does not mount the Docker socket.

## 5. Prepare a private project configuration

```sh
cp templates/project.example.yml .private/project.yml
```

The example uses a reserved `.invalid` domain and is not runnable against a real
application. Edit the private copy with the owner-verified staging origin and
scope. Then validate it offline:

```sh
.venv/bin/vapt validate .private/project.yml
.venv/bin/vapt scope-template .private/project.yml > .private/header-approval.json
```

The generated approval is intentionally invalid until an authorized owner supplies
the window, approver and exact paths. Do not invent those details or reuse another
project's approval. Stop here until the [pilot checklist](pilot-checklist.md) is
complete.

## Troubleshooting

| Symptom | What to do |
|---|---|
| Private clone fails | Verify your GitHub repository access; never put a token into the clone URL |
| `vapt` is not found | Use `.venv/bin/vapt` from the repository root |
| Browser executable or libraries missing | Install the optional browser components, or use `--html-only` |
| Output directory already exists | Choose a new run directory; do not overwrite previous evidence |
| Approval digest/window rejected | Reconfirm the exact config and obtain a fresh, active approval |
| Google/IAP returns 401/403 | Check the approved gateway identity; Cloud Run management access alone is insufficient |
| QA login fails | Stop and verify the test account privately; do not retry passwords in a loop |
| A run is incomplete | Read the recorded errors and cleanup status; do not treat zero findings as an all-clear |

For support, share the toolkit commit, operating system, command name, exit code
and a sanitized error. Do not share environment dumps, tokens, passwords or raw
application responses.
