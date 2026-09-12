"""Export fresh native Microsoft Agent Framework and smolagents evidence."""
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

PACKAGES = ("agent-framework-core", "smolagents", "pydantic", "huggingface-hub", "msgspec")
SDK_SOURCES = {
    "agent-framework-core": ("agent_framework/_tools.py", "agent_framework/_middleware.py",
                             "agent_framework/_agents.py", "agent_framework/_types.py"),
    "smolagents": ("smolagents/tools.py", "smolagents/agents.py", "smolagents/models.py", "smolagents/memory.py"),
}


def source_hashes():
    paths = [*sorted((ROOT / "yuanxingmu/adapters").glob("*.py")),
             *(ROOT / "yuanxingmu" / name for name in ("client.py", "broker.py", "authority.py", "actions.py", "mail_drafts.py", "mail_transport.py")),
             *(ROOT / "tests" / name for name in ("test_native_tools_client.py", "test_native_sdk_adapters.py",
                "test_additional_sdk_adapters.py", "test_autogen_llama_adapters.py", "test_microsoft_smolagents_adapters.py")),
             ROOT / "docs/microsoft-smolagents-adapters-requirements.txt", Path(__file__).resolve()]
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
        parser.error("Use a fresh output path; historical evidence is never overwritten")
    versions = {name: metadata.version(name) for name in PACKAGES}
    sdk_hashes = {package + ":" + name: hashlib.sha256(Path(metadata.distribution(package).locate_file(name)).read_bytes()).hexdigest()
                  for package, names in SDK_SOURCES.items() for name in names}
    import test_microsoft_smolagents_adapters
    import test_native_tools_client
    before = source_hashes()
    started_at, started = datetime.now(timezone.utc).isoformat(), time.monotonic()
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(test_microsoft_smolagents_adapters),
                                unittest.defaultTestLoader.loadTestsFromModule(test_native_tools_client)])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(suite)
    after = source_hashes()
    record = {
        "frameworks": ["microsoft_agent_framework", "smolagents"],
        "scope": "Installed native SDK tool registration and dispatch, genuine Broker Unix sockets, localhost receipts and temporary host files; only six registered Yuanxingmu tools",
        "registered_tools_only": True, "model_loop_run": False, "inference_run": False,
        "process_isolation_validated": False, "code_agent_executor_run": False, "legacy_evidence_reused": False,
        "microsoft_identity": "Actual FunctionTool.invoke tool_call_id, forwarded through direct and function middleware SDK dispatch; arbitrary context metadata cannot replace it",
        "smolagents_identity": "Explicit host-persisted nonce per dispatch; native chat-message tool-call ID is not injected into Tool.__call__; no binding rejects proposals",
        "smolagents_schema_limit": "Native get_tool_json_schema omits root additionalProperties; native declaration truthfully records this, nested constraints retained and complete closed runtime validation independently enforced",
        "sdk_private_methods_exercised": ["agent_framework._tools._auto_invoke_function"],
        "test_network_guard": "Only each fixture Broker socket and localhost receiver allowed; external DNS and connect_ex forbidden; prohibited attempts fail tests; not a product sandbox",
        "model_guard": "Agent registration uses SDK model subclasses whose generation entry points raise; zero model entry-point attempts required",
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
        "observations": test_microsoft_smolagents_adapters.OBSERVATIONS,
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
