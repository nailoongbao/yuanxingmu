import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from yuanxingmu.sandbox import sandbox_available


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux execution only")
class OperatorRunTests(unittest.TestCase):
    def test_operator_cli_resumes_persisted_task_and_refuses_workspace_identity_reset(self):
        bwrap = Path(os.environ["YUANXINGMU_TEST_BWRAP"]) if os.environ.get("YUANXINGMU_TEST_BWRAP") else None
        if not sandbox_available(bwrap=bwrap)["available"]:
            self.skipTest("bubblewrap unavailable")
        package = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="yxm-cli-") as folder:
            root = Path(folder)
            work = root / "workspace"
            work.mkdir()
            secret = root / "private.txt"
            secret.write_text("SYNTHETIC-CLI-PRIVATE")
            policy = root / "policy.json"
            policy.write_text(json.dumps({"resources": {"private": {"path": str(secret), "labels": ["internal"]}},
                "destinations": {"public": {"url": "http://127.0.0.1:1/public", "labels": []}}}))
            common = [sys.executable, "-m", "yuanxingmu", "run", "--policy", str(policy), "--state", str(root / "authority"),
                      "--task", "persistent-root", "--workspace", str(work)]
            if bwrap:
                common += ["--bwrap", str(bwrap)]

            def invoke(command):
                result = subprocess.run(command, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(package)},
                                        capture_output=True, text=True, timeout=15, close_fds=True)
                return result

            read = invoke(common + ["--new-task", "--", "/usr/bin/python3", "-m", "yuanxingmu.client", "read", "private"])
            self.assertEqual(read.returncode, 0, read.stderr + read.stdout)
            self.assertEqual(json.loads(read.stdout)["content"], "SYNTHETIC-CLI-PRIVATE")
            send = invoke(common + ["--", "/usr/bin/python3", "-m", "yuanxingmu.client", "send", "public", "--body", "encoded"])
            self.assertEqual(send.returncode, 2, send.stderr + send.stdout)
            self.assertFalse(json.loads(send.stdout)["allowed"])
            switched = list(common)
            switched[switched.index("persistent-root")] = "fresh-root"
            fresh = invoke(switched + ["--new-task", "--", "/usr/bin/true"])
            self.assertNotEqual(fresh.returncode, 0)
            self.assertIn("workspace_already_bound", fresh.stdout)
            log = (root / "authority/broker-events.jsonl").read_text()
            self.assertNotIn("SYNTHETIC-CLI-PRIVATE", log)


if __name__ == "__main__":
    unittest.main()
