"""Include actual Node plugin/Unix IPC contracts in ordinary unittest discovery."""
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux plugin and Unix socket contract")
class OpenClawMailToolsTests(unittest.TestCase):
    def test_actual_plugin_mail_contracts(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node is required to execute the actual plugin modules")
        source = Path(__file__).with_suffix(".mjs")
        result = subprocess.run([node, "--test", str(source)], cwd=source.parent.parent,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
