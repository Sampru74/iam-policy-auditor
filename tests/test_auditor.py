import unittest

from iam_policy_auditor.auditor import audit_policy


class AuditorTests(unittest.TestCase):
    def test_flags_full_admin_allow(self):
        findings = audit_policy({"Statement": {"Sid": "Admin", "Effect": "Allow", "Action": "*", "Resource": "*"}})

        self.assertEqual([finding["rule_id"] for finding in findings], ["IAM-001"])
        self.assertEqual(findings[0]["severity"], "critical")

    def test_flags_wildcard_action_and_resource(self):
        findings = audit_policy({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::demo-bucket/*"}]})

        self.assertEqual([finding["rule_id"] for finding in findings], ["IAM-002"])

    def test_flags_sensitive_iam_action(self):
        findings = audit_policy({"Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "arn:aws:iam::123456789012:user/demo"}]})

        self.assertEqual([finding["rule_id"] for finding in findings], ["IAM-004"])

    def test_ignores_deny_and_scoped_read_only_policy(self):
        policy = {"Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::demo-bucket/*"},
        ]}

        self.assertEqual(audit_policy(policy), [])

    def test_rejects_malformed_statement(self):
        with self.assertRaises(ValueError):
            audit_policy({"Statement": ["not-an-object"]})


if __name__ == "__main__":
    unittest.main()
