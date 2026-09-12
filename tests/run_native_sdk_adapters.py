"""Run installed SDK checks and write a fresh, explicitly bounded evidence file."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def source_hashes():
    paths = [*sorted((ROOT / "yuanxingmu/adapters").glob("*.py")),
             *(ROOT / "yuanxingmu" / name for name in ("client.py", "broker.py", "authority.py", "actions.py", "mail_drafts.py", "mail_transport.py")),
             ROOT / "tests/test_native_tools_client.py", ROOT / "tests/test_native_sdk_adapters.py", Path(__file__).resolve()]
    return {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a new output path; prior evidence is never overwritten")
    packages = ("langchain-core", "langgraph", "langgraph-prebuilt", "langgraph-checkpoint",
                "openai-agents", "openai", "pydantic-ai-slim", "pydantic")
    versions = {name: metadata.version(name) for name in packages}
    import test_native_sdk_adapters
    before = source_hashes()
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_native_*.py")
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    after = source_hashes()
    record = {
        "scope": "Native tool adaptation only: actual SDK registration and invocation, real Broker Unix sockets and local fixture effects",
        "model_loop_run": False, "process_isolation_validated": False, "legacy_mcp_evidence_reused": False,
        "test_network_guard": "socket.connect restricted by the test harness to each fixture Broker and its own HTTP receiver; not a product sandbox",
        "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3), "python": sys.version,
        "platform": platform.platform(), "packages": versions,
        "source_hashes": before, "sources_unchanged_during_run": before == after,
        "tests_run": result.testsRun, "passed": result.passed,
        "failures": [{"test": test.id(), "details": details} for test, details in result.failures],
        "errors": [{"test": test.id(), "details": details} for test, details in result.errors],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "observations": test_native_sdk_adapters.OBSERVATIONS,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    print(json.dumps({"evidence": str(args.output), "tests": result.testsRun,
                      "passed": len(result.passed), "skipped": len(result.skipped),
                      "sources_unchanged": before == after}))
    return 0 if result.wasSuccessful() and not result.skipped and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
