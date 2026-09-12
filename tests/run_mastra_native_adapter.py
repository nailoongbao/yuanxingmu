"""Record genuine Mastra/Unix Broker checks using an independent Linux Node SDK environment."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest
import warnings


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
ADAPTER = ROOT / "yuanxingmu/adapters/mastra"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [*ADAPTER.glob("*.mjs"), ADAPTER / "package.json", ADAPTER / "package-lock.json",
             *(ROOT / "yuanxingmu" / name for name in ("client.py", "broker.py", "authority.py", "actions.py", "mail_drafts.py", "mail_transport.py")),
             *(ROOT / "tests" / name for name in ("test_native_sdk_adapters.py", "test_additional_sdk_adapters.py",
                "test_mastra_native_adapter.py", "mastra_native_driver.mjs", "test_mastra_client.mjs")), Path(__file__).resolve()]
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in paths}


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed.append(test.id())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--sdk-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Use a fresh output path; prior evidence is never overwritten")
    if not sys.platform.startswith("linux"):
        parser.error("Genuine Broker evidence requires Linux")
    node, sdk_env = args.node.resolve(), args.sdk_env.resolve()
    if sdk_env.is_relative_to(ROOT):
        parser.error("Use a separate SDK environment outside the repository")
    node_version = subprocess.run([str(node), "--version"], check=True, text=True, capture_output=True).stdout.strip()
    major, minor, *_ = map(int, node_version.lstrip("v").split("."))
    if (major, minor) < (22, 13):
        parser.error("Mastra requires Node >=22.13")
    if digest(sdk_env / "package-lock.json") != digest(ADAPTER / "package-lock.json"):
        parser.error("Independent environment lockfile differs from the recorded adapter lockfile")
    runtime_copy = sdk_env / "adapter"
    runtime_copy.mkdir(exist_ok=True)
    if not runtime_copy.resolve().is_relative_to(sdk_env):
        parser.error("Adapter copy must remain inside the SDK environment")
    for source in ADAPTER.glob("*.mjs"):
        shutil.copyfile(source, runtime_copy / source.name)
    copied_before = {path.name: digest(path) for path in runtime_copy.glob("*.mjs")}
    expected_copies = {path.name: digest(path) for path in ADAPTER.glob("*.mjs")}
    if copied_before != expected_copies:
        parser.error("Runtime copy does not match repository adapter source")
    os.environ.update(YXM_MASTRA_NODE=str(node), YXM_MASTRA_ADAPTER=str(runtime_copy / "index.mjs"))
    sdk_root = sdk_env / "node_modules/@mastra/core"
    packages = {name: json.loads((sdk_env / "node_modules" / name / "package.json").read_text())["version"]
                for name in ("@mastra/core", "zod")}
    sdk_files = ("dist/tools/types.d.ts", "dist/tools/tool.d.ts", "dist/agent/agent.d.ts",
                 "dist/tool-CYfsCURf.js", "dist/agent-CEHR0Wd8.js")
    sdk_hashes = {name: digest(sdk_root / name) for name in sdk_files}
    import test_mastra_native_adapter
    before = source_hashes()
    started_at, started = datetime.now(timezone.utc).isoformat(), time.monotonic()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("default")
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult, failfast=True).run(
            unittest.defaultTestLoader.loadTestsFromModule(test_mastra_native_adapter))
    transport = subprocess.run([str(node), str(ROOT / "tests/test_mastra_client.mjs"), str(runtime_copy / "client.mjs")],
                               text=True, capture_output=True, timeout=30)
    try:
        transport_record = json.loads(transport.stdout)
    except ValueError:
        transport_record = {"failures": [{"error": transport.stderr or transport.stdout}], "passed": []}
    after = source_hashes()
    copied_after = {path.name: digest(path) for path in runtime_copy.glob("*.mjs")}
    sources_stable = before == after and copied_before == copied_after == expected_copies
    record = {
        "framework": "mastra", "scope": "Actual Mastra Tool/Agent registration, native tool execution and Agent.getToolsForExecution wrapper, genuine Unix Broker and local effects; no model loop",
        "model_loop_run": False, "inference_run": False, "process_isolation_validated": False,
        "contexts_supplied_by_fixture": True, "model_generated_call_identity_validated": False,
        "workflow_loop_run": False, "legacy_mcp_evidence_reused": False,
        "identity": "Agent toolCallId or separately namespaced host-persisted nonce; workflow runId is never a call identity",
        "resume_validation": "Actual Mastra resumeData path exercised; adapter repeats complete strict input validation before any Broker request",
        "network_guard": "Node tools may connect only to the fixture Broker path; Python Broker only to fixture localhost receiver; separate JS transport fixtures only use their own Unix sockets; test guard is not a product sandbox",
        "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - started, 3), "python": sys.version, "platform": platform.platform(),
        "node": node_version, "node_sha256": digest(node), "packages": packages,
        "package_lock_sha256": digest(sdk_env / "package-lock.json"), "sdk_source_hashes": sdk_hashes,
        "source_hashes": before, "runtime_copy_hashes": copied_before, "sources_unchanged_during_run": sources_stable,
        "native_tests_run": result.testsRun, "native_passed": result.passed,
        "failures": [{"test": test.id(), "details": details} for test, details in result.failures],
        "errors": [{"test": test.id(), "details": details} for test, details in result.errors],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "warnings": [{"category": item.category.__name__, "message": str(item.message)} for item in caught],
        "transport_tests": transport_record, "transport_exit_code": transport.returncode,
        "observations": test_mastra_native_adapter.OBSERVATIONS,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(record, output, ensure_ascii=True, indent=2)
        output.write("\n")
    ok = result.wasSuccessful() and not result.skipped and sources_stable and transport.returncode == 0 and not transport_record.get("failures")
    print(json.dumps({"evidence": str(args.output), "native_tests": result.testsRun,
                      "native_passed": len(result.passed), "transport_passed": len(transport_record["passed"]),
                      "skipped": len(result.skipped), "sources_unchanged": sources_stable, "passed": ok}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
