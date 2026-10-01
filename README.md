# Matt VAPT Kit

[![Toolkit checks](https://github.com/mattxslv/matt-vapt-kit/actions/workflows/test.yml/badge.svg)](https://github.com/mattxslv/matt-vapt-kit/actions/workflows/test.yml)

**Scoped security checks for staging, with private evidence you can review.**

Matt VAPT Kit (MVK) combines committed-code checks, approval-bound assessments and
HTML/PDF reporting in a local Python CLI. Checks are rule-based, with no AI service
calls. It is built to help a development team find and investigate issues before
an external vulnerability assessment and penetration test.

> [!IMPORTANT]
> **Private, supervised team pilot.** This is not a complete VAPT scanner, a
> security certification or an official CERT-PH report. A clean result means
> nothing was found in the tested scope, not that the application is secure.

[Getting started](docs/getting-started.md) |
[Assessment reference](docs/reference.md) |
[Team pilot checklist](docs/pilot-checklist.md) |
[Contributing](CONTRIBUTING.md)

## What you can do

| Capability | Scope |
|---|---|
| Check committed code | Gitleaks history checks, pnpm dependency audits and optional bundled Semgrep rules |
| Assess approved staging paths | Header-policy checks, repeat verification and opt-in bounded public-exposure checks |
| Compare endpoint permissions | Isolated DTAP test-account sessions, allowed-role controls and conservative response evidence |
| Access IAP-protected staging | Interactive browser login or an explicitly provisioned keyless service account |
| Review API authentication | Offline, heuristic review of committed Next.js route handlers |
| Produce private reports | Self-contained HTML, optional PDF and sanitized evidence figures |
| Exercise the detector locally | HTTPS fixtures, ownership/workflow lab and a separate release challenge |

Live role testing currently supports **DTAP's cookie-login contract only**.
Record ownership and workflow checks are local-lab capabilities, not live
assessment features. Bundled ZAP/Nuclei containers are dormant tools, not integrated
scan runners or scheduled jobs.

## First run: no live target required

Use Python **3.11+** and Git in a Linux-style shell. You need access to this private
GitHub repository. Docker, Google Cloud credentials and test-account passwords are
**not required** for this walkthrough.

```sh
git clone https://github.com/mattxslv/matt-vapt-kit.git
cd matt-vapt-kit

python3 -m venv .venv
.venv/bin/python -m pip install -e .

.venv/bin/vapt --version
.venv/bin/vapt validate templates/project.example.yml

mkdir -m 700 .private
.venv/bin/vapt report tests/fixtures/assessment.json \
  --reviewed --html-only --output .private/demo-report
```

Open `.private/demo-report/report.html`. It is clearly labeled as a **synthetic
example**. Validation and report generation do not contact a target; installation
downloads Python dependencies. On repeat runs, choose a new output directory:
existing evidence is never overwritten.

See [getting started](docs/getting-started.md) for PDF export, optional Docker tools,
environment requirements and troubleshooting.

## Move from local practice to staging

1. **Define the scope.** Verify the exact staging origin, owner, permitted paths,
   expected role policy and possible login side effects.
2. **Create a fresh approval.** The CLI binds it to the configuration digest and a
   short time window. A project YAML file alone never authorizes a run.
3. **Run and review.** Keep credentials and evidence private. Investigate findings,
   coverage gaps and unconfirmed session cleanup.

Follow the [team pilot checklist](docs/pilot-checklist.md) before a live run.
Gateway access and application test-account access are separate requirements.
The toolkit does not provision IAM, disable IAP, change an application or deploy it.

## Read the result, not just the finding count

| Result | Meaning |
|---|---|
| Confirmed finding | The check's evidence criteria were met; its stated scope still applies |
| Suspected finding | Supporting evidence is incomplete and needs review |
| Tested cell | The specified allowed, denied or violation criteria were assessed |
| Blocked / inconclusive | Access or evidence was insufficient; this is not a passing check |
| Not run / unsupported | No assessment was performed for that area |

Local benchmarks and a narrow live staging pilot support supervised use. They do
not establish a real-world accuracy percentage, full OWASP coverage or an absence
of historical data leaks. See the [benchmark limitations](docs/reference.md#accuracy-benchmark-and-limitations).

## Repository map

| Location | Purpose |
|---|---|
| [`vaptkit/`](vaptkit/) | CLI, scope validation, checks, access adapters and reporting |
| [`tests/`](tests/) | Routine local regressions and synthetic fixtures |
| [`release_tests/`](release_tests/) | Separately executed, versioned challenge cases |
| [`projects/`](projects/) | Internal project configurations, not standing approvals |
| [`templates/`](templates/) | Safe starter configuration and application CI template |
| [`docs/`](docs/) | Setup, team-pilot procedure and detailed reference |
| [`.github/workflows/`](.github/workflows/) | Toolkit checks and release challenge; no live target scans |

## Working on the toolkit

```sh
.venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=tests .venv/bin/python -m unittest discover -s release_tests -v
```

OpenSSL is required for local HTTPS coverage. The optional Juice Shop benchmark
uses an isolated Docker container and is not part of the default run.
See [contributing](CONTRIBUTING.md) for the full workflow.

Keep credentials, approvals, reports and browser profiles out of Git. Do not post
sensitive findings in public channels. See [security and evidence handling](SECURITY.md).
