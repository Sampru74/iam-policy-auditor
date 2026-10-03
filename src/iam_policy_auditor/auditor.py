from typing import Any

PRIVILEGE_MANAGEMENT_ACTIONS = {
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:setdefaultpolicyversion",
}


def audit_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ValueError("policy Statement must be an object or array of objects")

    findings = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise ValueError(f"Statement[{index}] must be an object")
        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        actions = _as_strings(statement.get("Action", []), f"Statement[{index}].Action")
        resources = _as_strings(statement.get("Resource", []), f"Statement[{index}].Resource")
        normalized_actions = {action.lower() for action in actions}
        sid = statement.get("Sid")
        statement_ref = str(sid) if sid is not None else f"Statement[{index}]"

        if "*" in normalized_actions and "*" in resources:
            findings.append(_finding(
                "IAM-001", "critical", statement_ref,
                "Allows all actions on all resources.", actions, resources,
            ))
            continue

        wildcard_actions = sorted(action for action in actions if "*" in action or "?" in action)
        if wildcard_actions:
            findings.append(_finding(
                "IAM-002", "high", statement_ref,
                "Grants wildcard actions; review whether every matched action is required.",
                wildcard_actions, resources,
            ))

        if "*" in resources:
            findings.append(_finding(
                "IAM-003", "medium", statement_ref,
                "Applies permissions to all resources; scope resources where supported.",
                actions, resources,
            ))

        sensitive = sorted(action for action in actions if action.lower() in PRIVILEGE_MANAGEMENT_ACTIONS)
        if sensitive:
            findings.append(_finding(
                "IAM-004", "high", statement_ref,
                "Includes IAM policy or credential management actions that warrant privilege review.",
                sensitive, resources,
            ))

    return findings


def _as_strings(value: Any, label: str) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
        raise ValueError(f"{label} must be a string or array of strings")
    return values


def _finding(
    rule_id: str,
    severity: str,
    statement: str,
    rationale: str,
    actions: list[str],
    resources: list[str],
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "statement": statement,
        "rationale": rationale,
        "actions": actions,
        "resources": resources,
    }
