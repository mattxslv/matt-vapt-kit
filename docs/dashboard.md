# Local browser dashboard

[README](../README.md) | [CLI setup](getting-started.md) | [Pilot checklist](pilot-checklist.md)

The dashboard packages Python, Chromium/PDF export and gcloud in one Docker image.
Teammates use a browser form instead of typing assessment commands. It is a
**local, single-operator application**, not a shared web service.

## Start it

Install Docker with Compose, clone the private toolkit repository and enter its
folder. From a terminal or **VS Code > Terminal > New Terminal**:

```sh
docker compose -f compose.dashboard.yml up --build
```

Wait for the dashboard startup message, then open:

**http://127.0.0.1:8765**

Use this exact URL, not a LAN address or a different hostname. The host/origin
checks intentionally reject other addresses. The initial build downloads pinned
base images and dependencies and can take several minutes. No host Python setup
is required and no assessment starts automatically.

Keep the terminal open. Press **Ctrl+C** to stop the foreground Compose session.
To stop/remove its containers later, while preserving the report volume:

```sh
docker compose -f compose.dashboard.yml down
```

Do not add `--volumes` unless you intend to delete the saved dashboard evidence.
Do not stop the container during a live run unless necessary: sign-out may be
unconfirmed and require manual cleanup.

## First run in the browser

1. Click **Create sample report**. No credentials or cloud access are needed.
2. Wait for **Your evidence is ready**.
3. Download HTML, PDF or the source JSON using the result buttons.
4. Open the downloaded report locally. It says **SYNTHETIC EXAMPLE**, not that
   a real assessment was performed.

Report generation is automatic for this flow. Nothing is sent to an external
reporting service. Downloads stay on your machine and must be reviewed before
sharing.

## Assess a staging project

1. Choose a project and **Header policy** or **DTAP endpoint roles**.
2. Confirm the displayed target, supply the authorized owner, choose the short
   window and exact paths. For roles, select accounts including a positive control.
3. Click **Check prerequisites & review scope**. This checks local browser
   readiness and configuration, not live access. It does not contact staging.
4. Review the exact URL, paths, selected accounts, request bound and expiry.
5. For roles, enter the selected QA emails and passwords in the browser form.
   Shared password variables have one field. The dashboard does not save these values.
6. Check the approval box and click **Approve & start assessment**.
7. Review findings, errors, coverage and cleanup. Download the report.

There is one active worker at a time. Each assessment runs in its own process;
credentials are passed over stdin, not CLI arguments or environment variables.
The server saves approvals and derived evidence, not passwords or raw response bodies.
The browser clears credential fields when starting the request and uses no localStorage.
JavaScript/Python memory is not guaranteed to be cryptographically zeroed; use a
trusted workstation without untrusted browser extensions.

The dashboard enforces windows of 1-30 minutes, 2-second request spacing and
20-second request timeouts. Role rules and scope validation are the same as the CLI.
The window begins when scope preview is created, not when the final button is pressed.
If it expires, return to the scope form and obtain a new approval.

**Current dashboard scope:** public/keyless-IAP header checks, configured DTAP role
checks and HTML/PDF generation. Browser-IAP login, arbitrary bearer tokens, public
exposure expansion, source/cloud reviews, Git hooks and Docker-based labs remain
CLI workflows. The dashboard never mounts the Docker socket.

## Project configuration

The `projects/` directory is mounted read-only. Add owner-reviewed YAML files there
and refresh the page to load them. Never put credentials in project files.
Invalid or unsupported configurations are shown as errors, not silently approved.

`projects/dtap-keyless.vapt.yml` describes the previously selected staging Cloud Run
origin and pilot service account with two QA roles. It is **not standing permission**
to scan and does not guarantee that temporary IAM grants remain active. The owner
must confirm the current target, access and policy before each run.

## Optional keyless Google IAP access

The default dashboard has **no access to your host's cloud credentials**. To use an
already-provisioned keyless staging identity, explicitly mount your gcloud login:

```sh
mkdir -p .private/dashboard-data
chmod 700 .private/dashboard-data

MVK_UID="$(id -u)" MVK_GID="$(id -g)" \
  docker compose -f compose.dashboard.yml -f compose.dashboard.gcloud.yml up --build
```

This override runs as your host UID/GID so it can read your existing
`~/.config/gcloud` directory, which is mounted **read-only**. It uses
`.private/dashboard-data` for private reports instead of the default named volume,
so the two modes have separate report histories. Stop the default dashboard first
if it is already running.

The gcloud directory must already exist and contain your authenticated user
credential database. The worker copies only its credential databases and CLI
configuration into a private temporary directory, lets gcloud refresh short-lived
credentials there, then removes that temporary copy. The container's `/tmp` is
memory-backed. Your original gcloud files are not changed.

**This mount is sensitive:** the existing cloud login may have broader permissions
than the pilot. Only run the reviewed image on a trusted machine, never expose the
dashboard to a network, and do not mount or share this directory casually. The
dashboard's origin/CSRF guards are not multi-user authentication.

The configured service account still needs IAP access and the caller still needs
JWT-signing permission. The application does not create or extend those grants,
disable IAP or deploy infrastructure. Google login and application QA passwords
are separate credentials.

## Storage, boundaries and failures

The default service publishes only `127.0.0.1:8765`, runs non-root with a read-only
root filesystem and dropped capabilities, and has no host Docker socket.
Unlike the offline tool containers, it has outbound networking for **explicitly
approved** staging checks and Google signing. It is not an internet-facing product.

Saved run directories and files use private permissions but are not encrypted.
The named volume is `dashboard-data` under this Compose project's prefix.
The optional gcloud mode uses `.private/dashboard-data` instead. Back up evidence
through your approved storage process.

Interrupted workers appear as **interrupted**, not completed. Partial JSON can
remain downloadable even when PDF generation fails. A failed or interrupted role
run may leave application sessions requiring owner cleanup. Reloading the browser
does not cancel the worker. Restarting the dashboard changes its browser request
token, so stale pages must be reloaded.

The UI displays only the last 30 runs; older evidence remains in storage. A local
user with access to this dashboard can read its reports and run approved jobs.
Do not use it on a shared/untrusted desktop or expose it through a tunnel without
a separate authentication/security design.

The Docker image adds no cloud resources or subscriptions. Approved live traffic,
existing cloud services, registry downloads and optional GitHub Actions still have
their normal usage terms. Local demo/report generation does not require GCP.
