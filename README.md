# IAM Policy Auditor

IAM Policy Auditor is an offline Python CLI that reviews AWS IAM identity-policy JSON and reports overly broad permissions and selected privilege-management capabilities. It does not call AWS APIs and needs no AWS account or credentials.

## Run

Requires Python 3.10 or newer; no third-party dependencies.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
iam-policy-auditor examples/sample_policy.json
```

The command exits with status `1` if findings exist, `0` if the policy passes these checks, and `2` for invalid input or file errors. Use `--json` for machine-readable findings.

## Checks

- `IAM-001`: an `Allow` statement grants `Action: "*"` on `Resource: "*"`.
- `IAM-002`: an `Allow` statement grants wildcard actions (including service-wide wildcards) on any resource.
- `IAM-003`: an `Allow` statement applies to all resources (`Resource: "*"`).
- `IAM-004`: an `Allow` statement grants selected IAM policy/role/user management actions. This is a review signal, not proof of exploitable privilege escalation.

Findings identify the statement `Sid` when present, observed actions/resources, severity, and rationale. Statements with `Effect: Deny` do not trigger these checks.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Limitations

This is a portfolio learning tool, not an AWS policy validator or a replacement for IAM Access Analyzer. It supports identity-policy JSON and does not fully evaluate AWS policy semantics, conditions, permissions boundaries, SCPs, resource policies, role trust policies, session policies, or service-specific behavior. A clean result does not establish that a policy is least-privilege or safe. Validate policies with AWS tooling and review the effective permissions in their deployment context. Examples are synthetic; never commit account-specific policies or secrets.
