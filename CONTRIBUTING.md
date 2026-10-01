# Contributing

Matt VAPT Kit is a private, staging-first toolkit in supervised pilot use.
Keep changes small, evidence-driven and explicit about coverage limitations.

## Development setup

Follow [getting started](docs/getting-started.md), then work from the repository root.
Use the existing Python virtual environment and unittest suite. Docker is optional
unless your change affects a container or scanner integration.

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Local HTTPS tests require OpenSSL. Review skips rather than treating a reduced
suite as full coverage. Routine tests do not contact DTAP, PEMEDES or Google login.
The separately enabled Juice Shop test is described in the
[benchmark reference](docs/reference.md#independent-application-cross-check).

## Before completing a change

1. Run the smallest relevant tests and add regressions for behavior changes.
2. Preserve scope checks, token redaction, account isolation and private output permissions.
3. Update documentation for changed commands, output shapes or dependencies.
4. Confirm that no real credentials, approvals, account data or reports are staged.
5. Use a concise, imperative commit message.

Changes to confirmation rules or report coverage must include misleading-response
cases and secure controls. A generic HTTP 200 is not proof of access, and a missing
finding is not proof of security.

## Release challenge

Run this separately before a candidate release:

```sh
PYTHONPATH=tests .venv/bin/python -m unittest discover -s release_tests -v
```

The workflow also supports manual dispatch and `v*` tags. It neither publishes
packages nor deploys applications. Keep the expected-outcome manifest distinct
from detection logic. Document and version substantive oracle changes; do not
change expectations just to make a failing result pass.

For container changes:

```sh
docker compose build kit
docker compose run --rm kit doctor
docker compose --profile report build report
```

The report image depends on the local core image. Neither runtime container gets
network access by default. Dependencies download during builds.

For browser-evidence changes, also run the local XSS lab:

```sh
MVK_RUN_XSS_LAB=1 .venv/bin/python -m unittest discover -s tests -p test_xss_lab.py -v
```

This requires the optional browser dependencies. An explicitly enabled lab fails
if those dependencies are missing; it does not silently skip. Toolkit CI runs the
same lab inside the network-disabled report container. See
[Cloud Armor and XSS](docs/cloud-armor-and-xss.md) for the evidence model.

## Boundaries

Do not run live assessments, enable cloud permissions, deploy applications or
rewrite application history as part of ordinary development. Those actions need
separate, explicit authorization. Keep local fixture data synthetic and disposable.
Follow [SECURITY.md](SECURITY.md) when reporting sensitive issues.
