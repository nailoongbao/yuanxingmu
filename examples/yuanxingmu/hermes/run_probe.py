"""Real Hermes terminal/file/provider probe with synthetic local services only."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import queue
import shlex
import subprocess
import sys
import tempfile
import threading


PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    hermes_home = output / "hermes-home"
    hermes_home.mkdir(mode=0o700)
    os.environ["HERMES_HOME"] = str(hermes_home)
    os.environ["TERMINAL_ENV"] = "yuanxingmu"
    os.environ["TERMINAL_CWD"] = "/workspace"
    os.environ["TERMINAL_CONTAINER_PERSISTENT"] = "false"
    (hermes_home / "config.yaml").write_text(
        "terminal:\n  backend: yuanxingmu\n  cwd: /workspace\n"
        "  container_persistent: false\n", encoding="utf-8",
    )
    hostile_cwd = output / "hostile-cwd"
    hostile_package = hostile_cwd / "yuanxingmu"
    hostile_package.mkdir(parents=True)
    host_import_marker = output / "unexpected-host-package-execution.txt"
    (hostile_package / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(host_import_marker)!r}).write_text('synthetic hostile package ran on host')\n"
        "raise RuntimeError('untrusted cwd package was imported')\n", encoding="utf-8",
    )
    os.chdir(hostile_cwd)

    from hermes_cli.plugins import PluginContext, PluginManager
    from hermes_cli.plugins_manifest import PluginManifest
    from tools.file_tools import read_file_tool, write_file_tool
    from tools.terminal_tool import terminal_tool, register_task_env_overrides, clear_task_env_overrides
    from tools.terminal_tool_lifecycle import cleanup_vm
    from yuanxingmu.broker import Broker, Destination, Resource

    module_path = Path(__file__).with_name("__init__.py")
    spec = importlib.util.spec_from_file_location("yuanxingmu_hermes_plugin", module_path)
    adapter = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = adapter
    spec.loader.exec_module(adapter)
    native_files = {
        "hermes_terminal": Path(inspect.getfile(terminal_tool)).resolve(),
        "hermes_files": Path(inspect.getfile(read_file_tool)).resolve(),
        "hermes_base_environment": Path(inspect.getfile(adapter.BaseEnvironment)).resolve(),
        "hermes_provider_interface": Path(inspect.getfile(adapter.TerminalEnvironmentProvider)).resolve(),
    }
    hermes_source = native_files["hermes_terminal"].parents[1]
    actual_commit = subprocess.run(
        ["/usr/bin/git", "-C", str(hermes_source), "rev-parse", "HEAD"],
        env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, check=True,
    ).stdout.strip()
    expected_commit = "2237be355906fbe6065ce1815711eee52b2d646e"
    if actual_commit != expected_commit:
        raise RuntimeError(f"Hermes source differs from the reviewed release: {actual_commit}")
    bound_sources = {
        "adapter": module_path, "probe": Path(__file__),
        **{name: PROJECT / f"yuanxingmu/{name}.py" for name in ("sandbox", "broker", "authority", "client", "worker", "receipts")},
        **native_files,
    }
    fixture = output / "private-business.txt"
    private_text = "SYNTHETIC-HERMES-PRIVATE-BUSINESS-20260911"
    fixture.write_text(private_text, encoding="utf-8")
    receipt_path = output / "receiver.jsonl"
    receiver_bootstrap = (
        "import runpy,sys; "
        f"sys.path.insert(0, {str(PROJECT)!r}); "
        "runpy.run_module('yuanxingmu.receipts', run_name='__main__')"
    )
    receiver = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", receiver_bootstrap, "--output", str(receipt_path)],
        env={"PATH": "/usr/bin:/bin"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    ready = queue.Queue()
    threading.Thread(target=lambda: ready.put(receiver.stdout.readline()), daemon=True).start()
    result = {
        "status": "incomplete", "scope": "Real Hermes terminal_tool/read_file_tool/write_file_tool, official provider registration, inherited BaseEnvironment.execute, real bubblewrap and local broker/receiver; no model or agent loop",
        "hermes_version": "v2026.9.7",
        "hermes_commit": actual_commit, "hermes_source": str(hermes_source),
        "hermes_distribution_version": importlib.metadata.version("hermes-agent"),
        "hostile_cwd": str(hostile_cwd), "trusted_core_root": str(adapter.CORE_ROOT),
        "native_calls": [], "assertions": {},
        "guards": {"skip_container_guards": False, "terminal_force": False},
        "source_files": {name: str(path) for name, path in bound_sources.items()},
        "source_hashes": {name: digest(path) for name, path in bound_sources.items()},
    }
    broker = provider = lease = None
    task_ids = []
    sockets = tempfile.TemporaryDirectory(prefix="yxm-hermes-")
    try:
        server = json.loads(ready.get(timeout=10))
        result["receiver"] = server
        broker = Broker(
            output / "broker-state", resources={"private": Resource(fixture, ("internal",))},
            destinations={
                "internal": Destination(f"http://127.0.0.1:{server['port']}/internal", ("internal",)),
                "public": Destination(f"http://127.0.0.1:{server['port']}/public"),
            },
        )
        main_task = broker.create_task(task_id="hermes-private-task")
        clean_task = broker.create_task(task_id="hermes-clean-task")
        task_ids = [main_task, clean_task]
        bindings = {}
        for index, task_id in enumerate(task_ids):
            workspace = output / "workspaces" / task_id
            workspace.mkdir(parents=True)
            broker.bind_workspace(task_id, workspace)
            endpoint = Path(sockets.name) / f"{index}.sock"
            broker.serve(task_id, endpoint)
            bindings[task_id] = adapter.TaskBinding(
                security_task_id=task_id, workspace=workspace, broker_socket=endpoint,
                readonly_paths=(PROJECT / "yuanxingmu",), env={"PYTHONPATH": str(PROJECT)},
            )
        provider = adapter.YuanxingmuProvider(bindings=bindings, bwrap=args.bwrap)
        result["task_bindings"] = {
            key: {"security_task_id": value.security_task_id, "workspace": str(value.workspace),
                  "broker_socket": str(value.broker_socket), "readonly_paths": [str(p) for p in value.readonly_paths],
                  "env": value.env}
            for key, value in bindings.items()
        }
        manager = PluginManager(scope_key=str(hermes_home))
        context = PluginContext(PluginManifest(name="yuanxingmu", kind="backend"), manager)
        lease = context.register_terminal_environment_provider(provider)
        if lease is None:
            raise RuntimeError("native_provider_registration_failed")
        result["availability"] = provider.availability
        for task_id in task_ids:
            register_task_env_overrides(task_id, {"env_type": "yuanxingmu", "cwd": "/workspace"})

        def call(name, **fields):
            tool = {"terminal": terminal_tool, "read_file": read_file_tool, "write_file": write_file_tool}[name]
            value = json.loads(tool(**fields))
            result["native_calls"].append({"tool": name, "arguments": fields, "result": value})
            return value

        # File tool runs FIRST: its own factory must select the provider.
        normal = call("write_file", path="/workspace/normal.txt", content="ordinary-hermes-work\n", task_id=main_task)
        normal_read = call("read_file", path="/workspace/normal.txt", task_id=main_task)
        normal_terminal = call("terminal", command="cat /workspace/normal.txt", task_id=main_task, timeout=15)
        host_read = call("read_file", path=str(fixture), task_id=main_task)
        acquired = call("terminal", command="python3 -m yuanxingmu.client read private", task_id=main_task, timeout=15)
        obtained = json.loads(acquired["output"])
        external = call("terminal", command="python3 -m yuanxingmu.client send public --body " + shlex.quote(obtained["content"]), task_id=main_task, timeout=15)
        internal = call("terminal", command="python3 -m yuanxingmu.client send internal --body 'synthetic internal correction'", task_id=main_task, timeout=15)

        tcp_code = (
            "import socket\n"
            f"connection = socket.create_connection(('127.0.0.1', {server['port']}), timeout=1)\n"
            "connection.sendall(b'SYNTHETIC-DIRECT-TCP')\n"
        )
        call("write_file", path="/workspace/direct_tcp.py", content=tcp_code, task_id=main_task)
        direct = call("terminal", command="python3 /workspace/direct_tcp.py", task_id=main_task, timeout=15)

        # Recreate only the native execution environment; do not claim this is
        # an autonomous Hermes session restore or delegate_task evaluation.
        cleanup_vm(main_task)
        repeated = call("terminal", command="python3 -m yuanxingmu.client send public --body 'retained private task'", task_id=main_task, timeout=15)
        clean = call("terminal", command="python3 -m yuanxingmu.client send public --body 'synthetic public release'", task_id=clean_task, timeout=15)
        broker.revoke(main_task)
        revoked = call("write_file", path="/workspace/after-revocation.txt", content="must-not-land", task_id=main_task)

        receipts = [json.loads(line) for line in receipt_path.read_text().splitlines()]
        checks = {
            "native_file_write_succeeded": (bindings[main_task].workspace / "normal.txt").read_text() == "ordinary-hermes-work\n",
            "native_file_read_succeeded": "ordinary-hermes-work" in normal_read.get("content", ""),
            "native_terminal_succeeded": normal_terminal.get("exit_code") == 0 and "ordinary-hermes-work" in normal_terminal.get("output", ""),
            "host_private_file_unreadable": private_text not in json.dumps(host_read) and bool(host_read.get("error") or host_read.get("success") is False),
            "broker_private_read_succeeded": obtained.get("allowed") is True and obtained.get("content") == private_text,
            "private_external_send_denied": json.loads(external["output"]).get("allowed") is False,
            "internal_correction_succeeded": json.loads(internal["output"]).get("allowed") is True,
            "direct_tcp_failed": direct.get("exit_code") != 0 and "ConnectionRefusedError" in direct.get("output", ""),
            "recreated_environment_retained_policy": json.loads(repeated["output"]).get("allowed") is False,
            "separate_clean_task_succeeded": json.loads(clean["output"]).get("allowed") is True,
            "revoked_task_write_did_not_land": not (bindings[main_task].workspace / "after-revocation.txt").exists() and bool(revoked.get("error") or revoked.get("success") is False),
            "only_two_expected_receipts": len(receipts) == 2 and {entry["body"] for entry in receipts} == {"synthetic internal correction", "synthetic public release"},
            "receipt_request_ids_match": {entry["request_id"] for entry in receipts} == {json.loads(internal["output"])["request_id"], json.loads(clean["output"])["request_id"]},
            "cwd_package_did_not_execute_on_host": not host_import_marker.exists(),
        }
        result["assertions"] = checks
        result["receipts"] = receipts
        result["status"] = "observed" if all(checks.values()) else "failed"
        if not all(checks.values()):
            raise AssertionError(checks)
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        for task_id in task_ids:
            cleanup_vm(task_id)
            clear_task_env_overrides(task_id)
        if provider:
            provider.cleanup()
            result["environments"] = [
                {"security_task_id": env.binding.security_task_id, "launches": env.launches,
                 "processes": env.process_observations()}
                for env in provider.environments
            ]
        if lease:
            lease.dispose()
        if broker:
            broker.close()
        if receiver.poll() is None:
            receiver.terminate()
        receiver.wait(timeout=5)
        result["receiver_returncode"] = receiver.returncode
        result["receiver_stderr"] = receiver.stderr.read()
        receiver.stdout.close()
        receiver.stderr.close()
        sockets.cleanup()
        result["source_hashes_after"] = {name: digest(path) for name, path in bound_sources.items()}
        result["assertions"]["tested_sources_unchanged"] = result["source_hashes"] == result["source_hashes_after"]
        result["assertions"]["cwd_package_did_not_execute_on_host"] = not host_import_marker.exists()
        result["assertions"]["all_launchers_reaped"] = bool(result.get("environments")) and all(
            process["reaped"] for environment in result["environments"] for process in environment["processes"]
        )
        if result["status"] == "observed" and not all(result["assertions"].values()):
            result["status"] = "incomplete"
        (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "assertions": result["assertions"], "result": str(output / "result.json")}, indent=2))
    if result["status"] != "observed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
