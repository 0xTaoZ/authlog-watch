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

        self.assertIn("SSH events parsed: 5", result.stdout)
        self.assertIn("198.51.100.10: 2", result.stdout)

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
        self.assertIn('"rule_id": "repeated_failed_source"', result.stdout)

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


if __name__ == "__main__":
    unittest.main()
