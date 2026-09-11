from __future__ import annotations

from contextlib import contextmanager
import os
import queue
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from defensecheck.process_witness import ProcessWitness


SUPPORTED = sys.platform == "win32" or (
    sys.platform.startswith("linux") and hasattr(os, "pidfd_open")
)


class ProcessWitnessTests(unittest.TestCase):
    @contextmanager
    def owned_child(self, *, skip_finally: bool = False):
        code = (
            "import os, sys\n"
            "try:\n"
            " print('ready', flush=True)\n"
            " sys.stdin.read()\n"
            + (" os._exit(0)\n" if skip_finally else "") +
            "finally:\n"
            " print('finally', flush=True)\n"
        )
        child = subprocess.Popen(
            [sys.executable, "-u", "-c", code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        ready = queue.Queue()
        reader = threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True)
        reader.start()
        try:
            self.assertEqual(ready.get(timeout=5).strip(), "ready")
            reader.join(timeout=1)
            yield child
        finally:
            if not child.stdin.closed:
                child.stdin.close()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Only this exact child, created above, may be reaped on failure.
                child.kill()
                child.wait(timeout=5)
                raise
            finally:
                child.stdout.close()
                child.stderr.close()
                reader.join(timeout=1)

    def finish(self, child):
        child.stdin.close()
        self.assertEqual(child.wait(timeout=5), 0)
        return child.stdout.read()

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_live_process_then_normal_exit(self):
        with self.owned_child() as child, ProcessWitness([child.pid]) as witness:
            live = witness.wait(timeout=0.02)
            self.assertTrue(live["all_captured_alive"])
            self.assertFalse(live["all_exited"])
            self.assertEqual(live["status"], "running")
            self.assertIsNone(child.poll())
            self.assertEqual(self.finish(child), "finally\n")
            exited = witness.wait(timeout=5)
            self.assertTrue(exited["all_exited"])
            self.assertEqual(exited["status"], "exited")
            self.assertEqual(exited["processes"][0]["pid"], child.pid)

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_exit_without_finally_is_not_claimed_graceful(self):
        with self.owned_child(skip_finally=True) as child, ProcessWitness([child.pid]) as witness:
            self.assertTrue(witness.wait(timeout=0)["all_captured_alive"])
            self.assertEqual(self.finish(child), "")
            report = witness.wait(timeout=5)
            self.assertTrue(report["all_exited"])
            self.assertEqual(report["graceful_shutdown"], "not_assessed")

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_closing_witness_does_not_stop_live_process(self):
        with self.owned_child() as child, ProcessWitness([child.pid]) as witness:
            self.assertTrue(witness.wait(timeout=0)["all_captured_alive"])
            witness.close()
            witness.close()
            self.assertIsNone(child.poll())
            report = witness.wait(timeout=0)
            self.assertEqual(report["status"], "incomplete")
            self.assertFalse(report["all_exited"])
            self.assertEqual(self.finish(child), "finally\n")

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_capturing_after_exit_is_incomplete(self):
        with self.owned_child() as child:
            self.finish(child)
            with ProcessWitness([child.pid]) as witness:
                report = witness.wait(timeout=0)
            self.assertEqual(report["status"], "incomplete")
            self.assertFalse(report["all_captured_alive"])
            self.assertFalse(report["all_exited"])
            self.assertTrue(report["processes"][0]["error"])

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_each_process_has_its_own_exit_observation(self):
        with self.owned_child() as first, self.owned_child() as second:
            with ProcessWitness([first.pid, second.pid]) as witness:
                self.assertTrue(witness.wait(timeout=0)["all_captured_alive"])
                self.finish(first)
                partial = witness.wait(timeout=0)
                states = {p["pid"]: p["state"] for p in partial["processes"]}
                self.assertEqual(states, {first.pid: "exited", second.pid: "running"})
                self.assertFalse(partial["all_exited"])
                self.assertEqual(partial["status"], "running")
                self.finish(second)
                self.assertTrue(witness.wait(timeout=5)["all_exited"])

    def test_empty_input_is_incomplete(self):
        with ProcessWitness([]) as witness:
            report = witness.wait(timeout=0)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["all_captured_alive"])
        self.assertFalse(report["all_exited"])

    def test_unsupported_platform_is_incomplete(self):
        with patch("defensecheck.process_witness.sys.platform", "unsupported-test-platform"):
            with ProcessWitness([os.getpid()]) as witness:
                report = witness.wait(timeout=0)
        self.assertEqual(report["backend"], "unsupported")
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["all_exited"])
        self.assertTrue(report["processes"][0]["error"])

    @unittest.skipUnless(SUPPORTED, "No native process-instance witness on this platform")
    def test_acquisition_permission_error_is_incomplete(self):
        backend = "_WindowsProcessHandle" if sys.platform == "win32" else "_LinuxPidfd"
        with patch(f"defensecheck.process_witness.{backend}", side_effect=PermissionError("denied")):
            with ProcessWitness([os.getpid()]) as witness:
                report = witness.wait(timeout=0)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["all_captured_alive"])
        self.assertFalse(report["all_exited"])
        self.assertIn("PermissionError", report["processes"][0]["error"])


if __name__ == "__main__":
    unittest.main()
