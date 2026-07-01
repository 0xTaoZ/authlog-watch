import subprocess
import sys
import unittest


class CliTest(unittest.TestCase):
    def test_help_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "authlog_watch", "--help"],
            check=True,
            capture_output=True,
            env={"PYTHONPATH": "src"},
            text=True,
        )

        self.assertIn("Review Linux auth.log SSH events", result.stdout)


if __name__ == "__main__":
    unittest.main()
