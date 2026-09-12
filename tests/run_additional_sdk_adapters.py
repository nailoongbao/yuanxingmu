"""Export fresh, bounded evidence for Google ADK, CrewAI and Agno tool adapters."""
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
import warnings


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

PACKAGES = ("google-adk", "google-genai", "crewai", "crewai-core", "agno", "pydantic", "openai")
SDK_SOURCES = {
    "google-adk": ("google/adk/tools/base_tool.py", "google/adk/tools/function_tool.py",
                   "google/adk/agents/context.py", "google/adk/agents/llm_agent.py"),
    "crewai": ("crewai/tools/base_tool.py", "crewai/tools/structured_tool.py", "crewai/hooks/tool_hooks.py"),
    "agno": ("agno/tools/function.py", "agno/agent/agent.py"),
}


def source_hashes():
    paths = [*sorted((ROOT / "yuanxingmu/adapters").glob("*.py")),
             *(ROOT / "yuanxingmu" / name for name in ("client.py", "broker.py", "authority.py", "actions.py", "mail_drafts.py", "mail_transport.py")),
             ROOT / "tests/test_native_tools_client.py", ROOT / "tests/test_native_sdk_adapters.py",
             ROOT / "tests/test_additional_sdk_adapters.py", Path(__file__).resolve()]
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
        parser.error("Use a fresh output path; prior evidence is never overwritten")
    versions = {name: metadata.version(name) for name in PACKAGES}
    sdk_hashes = {package + ":" + name: hashlib.sha256(Path(metadata.distribution(package).locate_file(name)).read_bytes()).hexdigest()
                  for package, names in SDK_SOURCES.items() for name in names}
    import test_additional_sdk_adapters
    import test_native_tools_client
    before = source_hashes()
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(test_additional_sdk_adapters),
                                unittest.defaultTestLoader.loadTestsFromModule(test_native_tools_client)])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    after = source_hashes()
    record = {
        "frameworks": ["google_adk", "crewai", "agno"],
        "scope": "Actual native SDK tool registration and invocation, real Broker Unix sockets and local fixture effects; no AutoGen adapter",
        "model_loop_run": False, "inference_run": False, "process_isolation_validated": False,
        "legacy_mcp_evidence_reused": False,
        "crewai_identity": "Explicit host-persisted nonce bound around each native tool dispatch; not a framework-supplied call ID",
        "test_network_guard": "connect allowed only to each fixture Broker or HTTP receiver, external DNS and connect_ex rejected; any prohibited attempt fails the test; not a product sandbox",
        "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3), "python": sys.version,
        "platform": platform.platform(), "packages": versions, "sdk_source_hashes": sdk_hashes,
        "installed_packages": dict(sorted((dist.metadata["Name"], dist.version) for dist in metadata.distributions())),
        "source_hashes": before, "sources_unchanged_during_run": before == after,
        "tests_run": result.testsRun, "passed": result.passed,
        "failures": [{"test": test.id(), "details": details} for test, details in result.failures],
        "errors": [{"test": test.id(), "details": details} for test, details in result.errors],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "warnings": [{"category": warning.category.__name__, "message": str(warning.message)} for warning in caught],
        "observations": test_additional_sdk_adapters.OBSERVATIONS,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    print(json.dumps({"evidence": str(args.output), "tests": result.testsRun, "passed": len(result.passed),
                      "skipped": len(result.skipped), "sources_unchanged": before == after}))
    return 0 if result.wasSuccessful() and not result.skipped and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
