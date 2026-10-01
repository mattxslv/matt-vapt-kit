# Security and evidence handling

## Report a toolkit issue privately

Contact the repository owner through an existing approved private team channel.
Do not post passwords, tokens, customer data, raw application responses or browser
profiles in an issue, pull request, screenshot or public service.

Provide the toolkit commit, affected command, a sanitized description and, when
possible, a reproduction using synthetic fixtures. Distinguish a weakness in this
toolkit from a finding about an assessed application.

If a credential may have been exposed, notify its owner and follow the team's
revocation/rotation procedure. Removing it from a file or log is not sufficient.

## Authorization is required

- Assess only owner-approved staging targets, paths, accounts and time windows.
- A valid project file or cloud-management permission is not an assessment approval.
- Do not disable access controls or widen permissions to obtain a passing result.
- Keyless access provisioning is a separate administrator-approved action.
- Login and logout can have session, audit and counter side effects.

## Handle artifacts as private data

The toolkit stores derived observations rather than raw response bodies or tokens.
Manual report inputs and source-review details may still be sensitive.
Review artifacts before export and distribution.

Use `.private/` or another approved private directory for local configurations,
approvals and reports. Generated folders/files use restrictive permissions, but
they are **not encrypted**. Git ignore rules are guardrails, not access control.
Never share the toolkit's saved IAP browser profile; it contains sensitive login state.

## Understand the limits

There is no certification, guarantee of complete detection or published support
SLA. Pilot users should use a reviewed commit and track security-related updates.
Confirmed means the stated check's evidence criteria were met. Blocked,
inconclusive and unsupported areas are not passing results.

An assessment with zero findings does not establish application security or prove
that no historical breach occurred. See the [reference](docs/reference.md) and
[pilot checklist](docs/pilot-checklist.md).
