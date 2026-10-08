# Getting started

[README](../README.md) | [Reference](reference.md) | [Team pilot](pilot-checklist.md)

Start with a synthetic report. Install additional tools only for the capability
you plan to use. None of the steps in the first-run walkthrough scans a live target.

**Want the interactive menu immediately?** From the toolkit folder, use `./install`
(Linux/macOS) or `powershell -ExecutionPolicy Bypass -File .\install.ps1` (Windows).
It bootstraps the local Python environment, installs the toolkit, and opens the
numbered menu. Re-running it later just reopens the menu. Windows support is not
yet piloted; see the [README warning](../README.md#install).

**Want to check a repository immediately, no menu?** From the toolkit folder, use
`./scan /path/to/your-project`. It bootstraps the local Python environment and runs
all supported independent committed-code checks with progress and a final table.
Docker must be running for the scanner stages. See [Without the menu](../README.md#without-the-menu).
The sample-report walkthrough below is optional and does not scan a repository.

This page walks through installation details, a sample report with expected
outputs, and optional dependencies.

## Open the right terminal

In VS Code, open the toolkit folder, then select **Terminal > New Terminal**.
Choose **Bash** for the commands below. You can also use an ordinary Linux terminal;
the toolkit does not require a VS Code extension or an AI skill.

These are Linux/Bash examples, not native PowerShell commands. A teammate pilot
on native Windows has not been completed. In a remote VS Code/SSH session, commands
run on the remote machine and reports must be downloaded to view locally.

## Requirements by capability

| Capability | Requirements |
|---|---|
| CLI, offline config validation, HTML reports | Python 3.11+, Git and repository access |
| Local HTTPS tests and release challenge | OpenSSL |
| PDF export and IAP browser login | The `report` extra, Playwright Chromium and browser system libraries |
| Push checks and optional scanner containers | Docker Engine with Compose |
| Keyless IAP access | gcloud signed into an approved identity; administrator-provisioned staging permissions |
| Read-only Cloud Armor review | gcloud and approved Cloud Run/Compute metadata read permissions |
| Local XSS browser lab | The `report` extra and Playwright Chromium; no cloud credentials or live target |
| Local WAF enforcement lab | Docker, local core image and pinned upstream ModSecurity/CRS image; no GCP resources |
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

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
vapt --version
vapt --help
vapt doctor --for html
```

**Activation makes the commands shorter:** `vapt` is the same executable as
`.venv/bin/vapt`, and `python` is `.venv/bin/python`. Activate the environment again
in each new terminal. For an already installed checkout, do not recreate the
environment; just enter the folder and run `source .venv/bin/activate`.
Examples later in this guide keep the full paths so they also work without
activation. No system-wide `sudo pip` install is needed.
The editable install keeps the CLI tied to this checkout; moving it requires
reinstallation, particularly when using Git hooks.

## 2. Try the offline path

With the environment activated:

```bash
vapt validate templates/project.example.yml
mkdir -p .private
chmod 700 .private
vapt report tests/fixtures/assessment.json \
  --reviewed --html-only --output .private/demo-report
```

Expected results:

- Validation reports `configuration: valid` and `scan_authorized: false`.
- `Report written to .private/demo-report/report.html` confirms the file was created.
- No application target is contacted and no cloud or QA credentials are loaded.

The CLI does **not** open your browser automatically. On a Linux desktop, run:

```bash
xdg-open .private/demo-report/report.html
```

Or use your browser's **Open File** command. In VS Code, opening the file in the
editor can show source code instead of the rendered page. Download the file first
when using a remote workspace. The rendered report says **SYNTHETIC EXAMPLE**:
the findings were supplied as fixture data, not discovered on your application.
`scan_authorized: false` from validation is expected and is not a failure.

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

`vapt doctor` without flags retains the bundled core-tool check. Use a task profile
to avoid treating unrelated scanner tools as prerequisites:

```sh
.venv/bin/vapt doctor --for html
.venv/bin/vapt doctor --for pdf
.venv/bin/vapt doctor --for local-tests
.venv/bin/vapt doctor --for push
.venv/bin/vapt doctor --for roles --config .private/project.yml
```

Other profiles are `iap-browser` and `iap-keyless`. Role checks with `--config`
select the relevant gateway dependencies. Without it, gateway checks are explicitly
omitted. Browser profiles launch and close a local Chromium process without opening
a target or signing in; interactive IAP also checks desktop availability. Missing
browser packages, libraries or display access are reported as unmet prerequisites.

These are prerequisite checks, **not full operational readiness**. Doctor does not
authenticate to Google, read QA credentials, contact targets, verify IAM, probe the
Docker daemon or pull images.
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
| Short commands stop working in a new terminal | Enter the toolkit folder and run `source .venv/bin/activate` |
| `Report written` appears but nothing opens | Open the HTML with `xdg-open` on Linux, or your browser's Open File command |
| Browser executable or libraries missing | Install the optional browser components, or use `--html-only` |
| Output directory already exists | Choose a new run directory; do not overwrite previous evidence |
| Approval digest/window rejected | Reconfirm the exact config and obtain a fresh, active approval |
| Google/IAP returns 401/403 | Check the approved gateway identity; Cloud Run management access alone is insufficient |
| QA login fails | Stop and verify the test account privately; do not retry passwords in a loop |
| Hidden password prompt is unavailable | Run `--prompt-passwords` in an interactive terminal, or use the configured environment variables in automation |
| A run is incomplete | Read the recorded errors and cleanup status; do not treat zero findings as an all-clear |

For support, share the toolkit commit, operating system, command name, exit code
and a sanitized error. Do not share environment dumps, tokens, passwords or raw
application responses.
