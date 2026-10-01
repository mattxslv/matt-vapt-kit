# Cloud Armor review and local XSS verification

[README](../README.md) | [Setup](getting-started.md) | [Reference](reference.md)

These are separate capabilities. Cloud Armor configuration does not establish
whether an application contains XSS, and an application's IAP login does not prove
that its traffic passes through Cloud Armor.

## Read-only Cloud Armor review

The command reads metadata, not application responses. An owner must authorize
the exact Google Cloud project and declared Cloud Run service. The current gcloud
identity needs the relevant Cloud Run and Compute read permissions; the toolkit
does not grant them.

From the repository root, using an already prepared private project configuration:

```sh
.venv/bin/vapt review-armor .private/project.yml \
  --gcp-project YOUR_STAGING_PROJECT \
  --service YOUR_STAGING_SERVICE \
  --region YOUR_REGION \
  --acknowledge-scope \
  --output .private/armor-review.json
```

Replace the uppercase placeholders with owner-confirmed resource identifiers.
Unlike a live application run, this metadata command does not use a time-window
approval file. `--acknowledge-scope` attests permission for the cloud inventory;
it is not permission to send attack traffic.

The collector uses four read-only gcloud commands:

1. Describe the exact Cloud Run service.
2. List serverless network endpoint groups in the project.
3. List backend services in the project.
4. List Cloud Armor security policies in the project.

It accepts at most 100 objects from each inventory, rejects larger or malformed
results, and bounds each command to 45 seconds and accepted JSON to 4 MB.
Permission failures do not become empty, passing inventories.
Project-wide metadata can be read even though only explicit associations to the
declared service are reported. The toolkit does not save raw metadata in its
artifacts; gcloud's own logging configuration is managed separately.

### What is reported

| Evidence | Interpretation |
|---|---|
| Explicit service -> regional NEG -> backend association | Configuration linkage, not proof that the public URL uses that backend |
| Attached backend security policy | Presence/resolution only, not proof of effective protection |
| Recognized standalone XSS/SQLi WAF function calls | Counts in non-preview and preview rules; arbitrary CEL is not evaluated |
| Earlier unconditional allow | Lower-priority WAF references in that policy can be unreachable |
| Preview-only XSS references | Observation about that policy, not an application XSS finding |
| Logging disabled or sampling zero requests | Backend request-evidence limitation, not absence of all logging |
| Rate-limit actions | Configured non-preview rules, not a tested rate limit |
| Missing associations, URL masks, unresolved policies or broad ingress | Explicit coverage gaps, never an all-clear |

All generated findings are **low-severity configuration observations**, not
confirmed application vulnerabilities. An absent policy is a coverage gap, not
automatically a vulnerability. Missing or unsupported metadata remains unknown.

The review does not resolve DNS, inspect URL maps/forwarding rules, evaluate
arbitrary CEL, test rule tuning or signature exclusions, exercise request/body
inspection limits, assess edge/hierarchical policies or send WAF test payloads.
`completed` means the supported metadata inventory completed without recorded
association gaps. It does **not** mean end-to-end Cloud Armor protection was verified.

### Add the snapshot to a report

```sh
.venv/bin/vapt report .private/assessment-001/assessment.json \
  --cloud-review .private/armor-review.json \
  --reviewed --output .private/combined-report
```

The snapshot must match the assessment's project and exact target URL. The service
to URL relationship remains operator-declared. Review the snapshot timestamp:
cloud metadata and application checks may have been collected at different times.
The report includes observations, backend summaries and gaps without upgrading
application XSS, ownership or workflow coverage.

## Local browser-confirmed XSS lab

This is a **local benchmark and evidence evaluator, not a live XSS scanner**.
There is no target-URL option and no live report profile for XSS.

Install the optional browser dependencies as described in [setup](getting-started.md),
then run:

```sh
MVK_RUN_XSS_LAB=1 .venv/bin/python -m unittest discover -s tests -p test_xss_lab.py -v
```

The lab starts a temporary loopback-only application and uses Playwright Chromium.
Its 12 cases cover reflected, DOM and stored XSS; escaped/text-only controls; CSP
blocking; a failed browser control; denied access; and JSON reflection.
Stored-XSS records are synthetic, in memory and cleared between cases.
Browser routes permit only the fixture origin and known paths. CI additionally
runs the lab in the network-disabled report container.

The detector requires a successful JavaScript control and two fresh attempts
showing the exact synthetic execution marker in the intended document.
Reflection alone does not confirm XSS. Browser failures, changed documents,
denials, missing controls, inconsistent execution and CSP-blocked attempts remain
inconclusive. Successful execution on an HTTP error page is still execution.
Only derived booleans/status values form evidence, not payloads, page bodies or
session data.

Expected outcomes are 3 confirmed fixture executions, 3 not reproduced and
6 inconclusive. **Not reproduced is not a claim that a page is secure.**
These are locally authored regressions, not an independent blind evaluation.
Live reflected/DOM scanning needs a separately approved bounded adapter. Live
stored XSS additionally needs explicit write, cleanup and disposable-data approval.

## Local ModSecurity and OWASP CRS lab

This exercises the upstream **ModSecurity + OWASP CRS Nginx image**, not a mock WAF
and not Google Cloud Armor. It requires Docker and the Python CLI environment.
No GCP project, billing account, cloud credentials or staging endpoint is involved.
Image downloads use the internet; runtime requests stay inside isolated containers.

From the repository root:

```sh
docker compose build kit
docker pull owasp/modsecurity-crs@sha256:ac057618e2c42e8192c000cb918ae1dff11446cf12beb6b23d4fa0065b0fe5be
MVK_RUN_WAF_LAB=1 .venv/bin/python -m unittest discover -s tests -p test_waf_lab.py -v
```

The dependency manifest is `tests/fixtures/waf-images.json`. The upstream WAF
image is digest-pinned; the fixture origin uses your locally built toolkit image,
resolved to an immutable local image ID before starting the run. The lab never
pulls images implicitly. Missing Docker/images fail an explicitly enabled run
rather than silently reducing coverage.

### What it verifies

Nine cases run in both `On` and `DetectionOnly` modes: four XSS/SQL-injection
request patterns, four legitimate controls and one application-generated 403.
Each case has a direct-origin control and two fresh requests through the WAF.

| Outcome | Required evidence |
|---|---|
| Blocked by WAF | Two 403s, no origin delivery, no origin marker, correlated audit statuses, expected CRS signature family and anomaly-blocking rule |
| Passed through | Two successful responses with matching markers and independently observed origin delivery |
| Origin denied | Matching 403 origin control and two matching application responses; not misclassified as WAF blocking |
| Inconclusive | Missing control, audit attribution, repetition or consistent evidence |

Enforcement expects four blocked attack cases, four allowed legitimate cases and
one correctly attributed application denial. Detection-only mode must still log
the expected attack signature families, but all eight non-denial cases reach the
origin. Logged detection is not mislabeled as blocking.

Zero false positives/misses is a gate **for this small corpus only**. Inconclusive
results fail the expected-outcome check; they are not silently counted as safe.
The origin only acknowledges synthetic requests. It does not execute SQL or
JavaScript, so accepted payloads do not establish an application exploit.
The separate browser XSS lab verifies script execution.

### Isolation and cleanup

The origin uses `--network=none`; the WAF shares that origin's loopback-only network
namespace. No host ports or Docker socket are exposed. Each container has a
512 MiB memory cap, one CPU, a 128-PID limit, dropped capabilities and
`no-new-privileges`. Only the origin's synthetic handler is mounted read-only.
No host credentials, repository source trees or live data are mounted.

The upstream WAF requires a writable container filesystem for generated config.
Its audit file contains synthetic request metadata and stays in that disposable
layer. Request/response bodies are excluded from audit parts; synthetic query
payloads and match text can still appear. Docker log persistence is disabled.
The test reads audits in memory and retains only correlated status/rule evidence.
Cleanup stops only the containers it created, removes their writable layers via
`--rm`, and verifies they are gone. Downloaded images remain cached for future runs.

The GitHub **Local WAF lab** workflow is manual-only. It needs no cloud credentials
and creates no GCP resources. GitHub Actions usage can still consume runner minutes
under your organization's plan; run on your workstation to avoid that usage.

Results mean **local WAF enforcement verified in the tested cases**. Cloud Armor's
rule translation, routing, IAM, logging and actual enforcement still require a
separate Google-hosted assessment.

## Sources

- [Cloud Armor integrations and IAP](https://docs.cloud.google.com/armor/docs/integrating-cloud-armor)
- [Preconfigured WAF rules and inspection limits](https://docs.cloud.google.com/armor/docs/configure-waf)
- [Upstream OWASP CRS Docker image and settings](https://github.com/coreruleset/modsecurity-crs-docker)
