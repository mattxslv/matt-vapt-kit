# Supervised team pilot

[README](../README.md) | [Setup](getting-started.md) | [Reference](reference.md)

Use one teammate and one small, approved staging scope first. This is a usability
and operational-readiness pilot, not a certification or an independent accuracy study.

## Before the run

- [ ] The maintainer supplies a reviewed full toolkit commit SHA.
- [ ] The teammate installs it independently and exports the synthetic HTML report.
- [ ] The owner verifies the exact staging host, permitted endpoints and test window.
- [ ] The expected allowed/denied role policy is reviewed against application behavior.
- [ ] Synthetic accounts and data are ready; email, payment and other side effects are understood.
- [ ] Credentials are supplied privately, not through chat, Git, CLI arguments or shell history.
- [ ] The operator knows how to revoke sessions if cleanup is unconfirmed.
- [ ] Evidence storage and permitted recipients are agreed in advance.

Project files under `projects/` are starting configurations, not reusable live
approvals. A prior successful run does not authorize a new target, window or operator.

## Choose the access path

| Target | Access |
|---|---|
| Public staging endpoint | No gateway credential, but an approved scope is still required |
| IAP with interactive access | Operator signs into the dedicated browser; saved profiles contain sensitive login state |
| IAP with keyless access | Dedicated staging service account and explicitly approved signing/access grants |
| DTAP role matrix | Gateway access if required, plus separate DTAP QA account credentials |

Do not disable IAP or repurpose a production, deployment or secret-rotation identity.
The toolkit does not create identities or change IAM. An administrator must approve
and provision keyless access separately, preferably with time-limited grants.
See [IAP access](reference.md#access-through-google-iap).

The initial DTAP pilot should stay with a single reviewed GET route, one allowed-role
control and one denied-role account. Login and logout POSTs can create sessions,
audit records and login counters. Business-record mutations are not part of this pilot.

## Run only the approved scope

From the repository root, after reviewing your private configuration:

```sh
.venv/bin/vapt scope-template .private/project.yml > .private/header-approval.json
```

The owner completes the approval. Only then:

```sh
.venv/bin/vapt run .private/project.yml \
  --approval .private/header-approval.json --acknowledge-scope \
  --output .private/header-run-001
```

For the DTAP-specific role adapter, the private project configuration must also
contain reviewed `role_testing` accounts and routes. The generic starter template
does not configure application login:

```sh
.venv/bin/vapt scope-template .private/project.yml --roles > .private/role-approval.json
# Owner reviews the selected account IDs, paths, time window and role_login approval.
# Supply the configured QA environment variables through an approved private method.
.venv/bin/vapt roles .private/project.yml \
  --approval .private/role-approval.json --acknowledge-scope \
  --prompt-passwords --output .private/role-run-001
```

Set the configured QA **email** environment variables before the run.
`--prompt-passwords` asks for missing passwords using hidden terminal input.
Accounts sharing a password-variable name share one prompt. Existing password
environment variables take precedence; the prompt does not overwrite them or
save new values to files or environment variables. For unattended use, omit the
flag and supply all configured variables through your approved secret mechanism.
Do not pipe passwords into the command or put them in shell arguments.

The prompt requires an interactive terminal and refuses an echo-enabled fallback.
Cancellation, invalid input and scope expiry abort before gateway login or
assessment traffic. Time spent at the prompt consumes the approval window.

Do not run either command with an unreviewed template. Redirects, rate limits,
server errors, transport failures and expired scope stop the runner. Do not keep
retrying to obtain a passing result. Stopped runs can leave sessions requiring
manual cleanup.

After each assessment, the terminal summary shows finding counts, coverage gaps
and, for roles, tested/blocked/inconclusive/unattempted cells and sign-out status.
The summary does not generate a report automatically. It points to the JSON for
review; export HTML/PDF separately as described below.

## Review before sharing

- [ ] Every expected matrix cell is accounted for, including blocked or unattempted cells.
- [ ] Findings are independently reproduced or clearly retained as suspected.
- [ ] A sample of passing controls is manually checked.
- [ ] Inconclusive checks are not counted as passing or removed to improve the score.
- [ ] Logout acknowledgement is distinguished from proven server-side revocation.
- [ ] Reports are reviewed for private content before export and shared only with approved recipients.
- [ ] Temporary access grants and sessions are expired, revoked or otherwise accounted for.

After inspecting the assessment JSON:

```sh
.venv/bin/vapt report .private/role-run-001/assessment.json \
  --reviewed --output .private/role-report-001
```

Use `--html-only` if browser export is not installed. Never commit the output.

## Readiness decision

Advance beyond the initial pilot only when the teammate can install, run and
interpret the tool without undocumented help, known discrepancies have been
resolved, and evidence handling and cleanup work as documented.

A successful pilot does **not** establish broad vulnerability detection accuracy.
The local challenge suite was inspected while improving detection, so it is not a
blind holdout. Independent evaluation and manual security review remain necessary.
Live ownership/workflow testing and comprehensive VAPT remain outside current coverage.
