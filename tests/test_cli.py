import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

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
                str(PROJECT_ROOT / "samples" / "auth.log"),
            ],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": str(PROJECT_ROOT / "src")},
            text=True,
        )

        self.assertIn("SSH events parsed: 5", result.stdout)
        self.assertIn("198.51.100.10: 2", result.stdout)


if __name__ == "__main__":
    unittest.main()
