import argparse
import json
import sys
from pathlib import Path
from typing import Any

from iam_policy_auditor.auditor import audit_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iam-policy-auditor", description="Review an AWS IAM identity policy JSON file offline.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args(argv)

    try:
        policy: Any = json.loads(args.policy.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            raise ValueError("policy document must be a JSON object")
        findings = audit_policy(policy)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"iam-policy-auditor: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(findings, indent=2))
    elif not findings:
        print("No findings from the configured checks.")
    else:
        for finding in findings:
            print(
                f"[{finding['severity'].upper()}] {finding['rule_id']} "
                f"{finding['statement']}: {finding['rationale']}"
            )

    print(f"Reviewed {len(policy.get('Statement', [])) if isinstance(policy.get('Statement', []), list) else 1} statement(s); found {len(findings)} finding(s).", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
