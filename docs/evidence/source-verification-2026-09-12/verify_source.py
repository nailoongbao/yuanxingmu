"""Local source, unittest and installed-wheel evidence; never invokes a model."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
OMIT = {"__pycache__", "node_modules", ".git", "build", "dist"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def utc():
    return datetime.now(timezone.utc).isoformat()


def source_manifest():
    paths = {ROOT / name for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE.md")}
    for directory in ("defensecheck", "yuanxingmu", "tests", "install", "LICENSES"):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and not OMIT.intersection(path.relative_to(ROOT).parts):
                if path.suffix in {".py", ".mjs", ".js", ".json", ".css", ".html", ".svg", ".md", ".yaml", ".yml", ".txt"}:
                    if directory == "install" and "evidence" in path.relative_to(ROOT).parts:
                        continue
                    paths.add(path)
    return {str(path.relative_to(ROOT)).replace("\\", "/"): {"sha256": digest(path), "bytes": path.stat().st_size}
            for path in sorted(paths)}


def run_suite(label):
    OUT.mkdir(parents=True, exist_ok=True)
    before = source_manifest()
    save(OUT / f"{label}-source-before.json", before)
    started, elapsed = utc(), time.monotonic()
    log_path = OUT / f"{label}-unittest.log"
    print(f"Starting {label} unittest discovery; log: {log_path}", flush=True)
    sys.path.insert(0, str(ROOT))
    os.chdir(ROOT)
    with log_path.open("w", encoding="utf-8", buffering=1) as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    after = source_manifest()
    save(OUT / f"{label}-source-after.json", after)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    summary = {
        "started_at": started, "finished_at": utc(), "elapsed_seconds": round(time.monotonic() - elapsed, 3),
        "scope": "All unittest cases discovered under tests, equivalent to python -m unittest discover -s tests -v. Counts are tests, not attacks.",
        "platform": platform.platform(), "python": sys.version, "executable": sys.executable,
        "tests_run": result.testsRun,
        "passed": result.testsRun - len(result.skipped) - len(result.errors) - len(result.failures) - len(result.expectedFailures) - len(result.unexpectedSuccesses),
        "skipped": len(result.skipped), "failures": len(result.failures), "errors": len(result.errors),
        "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
        "successful": result.wasSuccessful(), "skip_reasons": dict(Counter(reason for _, reason in result.skipped)),
        "skipped_tests": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "failure_details": [{"test": str(test), "traceback": detail} for test, detail in result.failures + result.errors],
        "source_changes_during_run": changed, "source_file_count": len(before),
        "source_manifest_before": f"{label}-source-before.json", "source_manifest_after": f"{label}-source-after.json",
        "log": log_path.name, "log_sha256": digest(log_path),
    }
    save(OUT / f"{label}-unittest.json", summary)
    print(json.dumps({key: summary[key] for key in ("tests_run", "passed", "skipped", "failures", "errors", "successful", "source_changes_during_run")}), flush=True)
    return 0 if result.wasSuccessful() and not changed else 1


def command(args, cwd, log, env=None):
    log.write("$ " + " ".join(str(arg) for arg in args) + "\n")
    log.flush()
    run = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    if run.returncode:
        raise RuntimeError(f"Verification command failed ({run.returncode}): {args[0]}")


def installed_check(manifest_path, result_path):
    from importlib.resources import files
    import defensecheck
    import yuanxingmu
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    prefix = Path(sys.prefix).resolve()
    imports = {name: str(Path(module.__file__).resolve()) for name, module in (("defensecheck", defensecheck), ("yuanxingmu", yuanxingmu))}
    assert all(Path(path).is_relative_to(prefix) for path in imports.values()), imports
    assert not Path.cwd().is_relative_to(ROOT)
    checked = []
    for name, source in expected.items():
        package, relative = name.split("/", 1)
        installed = files(package).joinpath(relative)
        raw = installed.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        assert raw and actual == source["sha256"], name
        if name.endswith(".json"):
            json.loads(raw)
        elif name.endswith(".py"):
            ast.parse(raw.decode("utf-8"), filename=name)
        elif name.endswith("plugin.yaml"):
            values = dict(line.split(": ", 1) for line in raw.decode("utf-8").splitlines() if line.strip())
            assert values["name"] == "yuanxingmu" and values["kind"] == "backend"
        checked.append({"path": name, "sha256": actual, "bytes": len(raw), "installed_path": str(installed)})
    save(result_path, {"python": sys.version, "executable": sys.executable, "prefix": str(prefix), "cwd": str(Path.cwd()),
                       "version": importlib.metadata.version("agent-defense-check"), "imports": imports,
                       "assets_checked": len(checked), "assets": checked,
                       "scope": "Byte-for-byte packaged source/assets; Python AST, JSON and simple Hermes manifest checked. No Agent/model execution."})
    return 0


def run_package():
    OUT.mkdir(parents=True, exist_ok=True)
    started = utc()
    before = source_manifest()
    save(OUT / "wheel-source-before.json", before)
    scratch = Path(tempfile.mkdtemp(prefix="yxm-source-verification-20260912-"))
    stage, build_env, install_env = scratch / "source", scratch / "build-env", scratch / "installed-env"
    outside = scratch / "outside-source"
    stage.mkdir()
    outside.mkdir()
    for directory in ("defensecheck", "yuanxingmu", "LICENSES"):
        shutil.copytree(ROOT / directory, stage / directory, ignore=shutil.ignore_patterns(*OMIT, "*.pyc"))
    for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE.md"):
        shutil.copy2(ROOT / name, stage / name)
    for name, value in before.items():
        if (stage / name).is_file():
            assert digest(stage / name) == value["sha256"], name
    metadata = tomllib.loads((stage / "pyproject.toml").read_text(encoding="utf-8"))
    expected = {}
    for package, globs in metadata["tool"]["setuptools"]["package-data"].items():
        base = stage / package.replace(".", "/")
        for pattern in globs:
            for path in base.glob(pattern):
                if path.is_file():
                    name = path.relative_to(stage).as_posix()
                    expected[name] = before[name]
    save(OUT / "wheel-expected-assets.json", expected)
    wheels = OUT / "dist"
    wheels.mkdir(exist_ok=True)
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(key, None)
    log_path = OUT / "wheel-build-install.log"
    print(f"Building a fresh source copy; log: {log_path}", flush=True)
    with log_path.open("w", encoding="utf-8", buffering=1) as log:
        command([sys.executable, "-m", "venv", build_env], outside, log, env)
        build_python = build_env / "bin/python"
        command([build_python, "-m", "pip", "install", "--only-binary=:all:", "setuptools==83.0.0", "wheel==0.48.0", "packaging==26.0"], outside, log, env)
        command([build_python, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", wheels, stage], outside, log, env)
        wheel = wheels / f"agent_defense_check-{metadata['project']['version']}-py3-none-any.whl"
        assert wheel.is_file()
        with zipfile.ZipFile(wheel) as archive:
            for name, value in expected.items():
                assert hashlib.sha256(archive.read(name)).hexdigest() == value["sha256"], name
            archive_names = archive.namelist()
            assert not any("node_modules/" in name or "__pycache__/" in name for name in archive_names)
        command([sys.executable, "-m", "venv", install_env], outside, log, env)
        installed_python = install_env / "bin/python"
        command([installed_python, "-m", "pip", "install", "--no-index", "--no-deps", wheel], outside, log, env)
        cli_checks = [
            [install_env / "bin/defensecheck", "--help"],
            [install_env / "bin/yuanxingmu", "--help"],
            [installed_python, "-I", "-m", "yuanxingmu", "desk", "--help"],
            [installed_python, "-I", "-m", "yuanxingmu", "hermes", "init", "--help"],
        ]
        for args in cli_checks:
            command(args, outside, log, env)
        command([installed_python, "-I", Path(__file__).resolve(), "installed", "--manifest", OUT / "wheel-expected-assets.json", "--result", OUT / "wheel-installed.json"], outside, log, env)
        installed = json.loads((OUT / "wheel-installed.json").read_text(encoding="utf-8"))
        syntax_files = [item["installed_path"] for item in installed["assets"] if item["path"].endswith((".mjs", ".js"))]
        node = shutil.which("node")
        assert node, "Node is required for syntax-only checks of packaged JS; no SDK installation is needed"
        for path in syntax_files:
            command([node, "--check", path], outside, log, env)
        assert installed["version"] == metadata["project"]["version"]
    after = source_manifest()
    save(OUT / "wheel-source-after.json", after)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    summary = {"started_at": started, "finished_at": utc(), "successful": not changed,
               "scope": "Pure Python wheel from a fresh source copy, installed without dependencies/network into a new venv. CLI/import/assets checked outside the repository. No Hermes/npm installation, SDK end-to-end suite, or model call.",
               "scratch": str(scratch), "build_tools": {"setuptools": "83.0.0", "wheel": "0.48.0", "packaging": "26.0"},
               "wheel": wheel.relative_to(OUT).as_posix(), "wheel_sha256": digest(wheel), "wheel_bytes": wheel.stat().st_size,
               "package_version": installed["version"], "assets_checked": len(expected), "cli_checks": [[str(arg) for arg in args] for args in cli_checks],
               "javascript_syntax_checks": len(syntax_files), "source_changes_during_build": changed,
               "source_manifest_before": "wheel-source-before.json", "source_manifest_after": "wheel-source-after.json",
               "installed_evidence": "wheel-installed.json", "log": log_path.name, "log_sha256": digest(log_path)}
    save(OUT / "wheel-verification.json", summary)
    print(json.dumps({key: summary[key] for key in ("successful", "package_version", "assets_checked", "javascript_syntax_checks", "source_changes_during_build")}), flush=True)
    return 0 if not changed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("suite", "package", "installed"))
    parser.add_argument("--label")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    if args.mode == "suite":
        raise SystemExit(run_suite(args.label))
    if args.mode == "installed":
        raise SystemExit(installed_check(args.manifest, args.result))
    if args.label:
        if not args.label.replace("-", "").isalnum():
            parser.error("Package label must use letters, digits or hyphens")
        OUT = OUT / args.label
    raise SystemExit(run_package())
