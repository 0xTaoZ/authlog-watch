import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = PROJECT_ROOT / "samples" / "auth.log"


class CliTest(unittest.TestCase):
    def test_help_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "authlog_watch", "--help"],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn("Review Linux auth.log SSH events", result.stdout)

    def test_sample_report_runs(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
            ],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn("SSH events parsed: 10", result.stdout)
        self.assertIn("Invalid users: 3", result.stdout)
        self.assertIn("Accepted publickeys: 1", result.stdout)
        self.assertIn("Connection closed: 1", result.stdout)
        self.assertIn("Received disconnects: 1", result.stdout)
        self.assertIn("Unable to negotiate: 1", result.stdout)
        self.assertIn("198.51.100.10: 2", result.stdout)
        self.assertIn("203.0.113.50: 3", result.stdout)
        self.assertIn("Successful login source IPs", result.stdout)
        self.assertIn("203.0.113.77: 1", result.stdout)
        self.assertIn("Successful login users", result.stdout)
        self.assertIn("deploy: 1", result.stdout)
        self.assertIn("Pre-auth disconnect source IPs", result.stdout)
        self.assertIn("192.0.2.44: 1", result.stdout)
        self.assertIn("192.0.2.45: 1", result.stdout)
        self.assertIn("203.0.113.88: 1", result.stdout)
        self.assertIn("mixed_auth_outcome_source", result.stdout)

    def test_threshold_flag_prints_findings(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
                "--failed-threshold",
                "2",
            ],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn("Findings", result.stdout)
        self.assertIn("repeated_failed_source", result.stdout)
        self.assertIn("threshold: 2", result.stdout)

    def test_limit_caps_top_sections(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
                "--limit",
                "1",
            ],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn("203.0.113.50: 3", result.stdout)
        self.assertNotIn("198.51.100.10: 2", result.stdout)
        self.assertIn("Successful login source IPs\n- 198.51.100.10: 1", result.stdout)
        self.assertNotIn("203.0.113.77: 1", result.stdout)

    def test_json_output_includes_findings(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
                "--failed-threshold",
                "2",
                "--json",
            ],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn('"findings": [', result.stdout)
        self.assertIn('"connection_closed": 1', result.stdout)
        self.assertIn('"received_disconnects": 1', result.stdout)
        self.assertIn('"unable_to_negotiate": 1', result.stdout)
        self.assertIn('"top_success_source_ips": [', result.stdout)
        self.assertIn('"top_success_users": [', result.stdout)
        self.assertIn('"top_preauth_source_ips": [', result.stdout)
        self.assertIn('"rule_id": "repeated_failed_source"', result.stdout)
        self.assertIn('"rule_id": "mixed_auth_outcome_source"', result.stdout)
        self.assertIn('"success_count": 1', result.stdout)

    def test_threshold_must_be_positive(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
                "--failed-threshold",
                "0",
            ],
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be at least 1", result.stderr)

    def test_limit_must_be_positive(self):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "authlog_watch",
                str(SAMPLE_LOG),
                "--limit",
                "0",
            ],
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be at least 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
