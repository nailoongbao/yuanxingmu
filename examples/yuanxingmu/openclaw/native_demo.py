"""Real installed OpenClaw CLI, synthetic model replies, real worker/broker effects.

Run on Linux. Does not install dependencies, contact a paid model, or read user config.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import uuid

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
sys.path.insert(0, str(REPO))

from yuanxingmu.broker import Broker, Destination, Resource
from yuanxingmu.sandbox import sandbox_available


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def private_copy(source, destination):
    # WSL-mounted Windows files can report 0777. Do not preserve that mode in
    # trusted Linux plugin/core copies: OpenClaw correctly refuses writable code.
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__"))
    destination.chmod(0o700)
    for item in destination.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.receipts.append({"path": self.path, "payload": value,
            "authorization": self.headers.get("Authorization")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"LOCAL_RECEIPT")

    def log_message(self, *args):
        pass


class FixtureModel(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        state = self.server.fixture
        state["requests"].append({"phase": state["phase"], "path": self.path, "body": body})
        tools = [item.get("function", {}).get("name") for item in body.get("tools", [])]
        if self.path != "/v1/chat/completions" or (not state["issued"] and "exec" not in tools):
            self.send_error(400, "This fixture requires the native exec tool and chat-completions route")
            return
        if not state["issued"]:
            state["issued"] = True
            delta = {"role": "assistant", "tool_calls": [{"index": 0,
                "id": "synthetic_" + state["phase"], "type": "function",
                "function": {"name": "exec", "arguments": json.dumps({"command": state["command"]})}}]}
            finish = "tool_calls"
        else:
            delta = {"role": "assistant", "content": "Synthetic native execution fixture complete."}
            finish = "stop"
        envelope = {"id": "fixture-" + uuid.uuid4().hex, "object": "chat.completion.chunk",
                    "created": int(time.time()), "model": "synthetic-exec"}
        if body.get("stream"):
            chunks = [{**envelope, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                      {**envelope, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                       "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}}]
            data = "".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
        else:
            delta.pop("index", None)
            for call in delta.get("tool_calls", []):
                call.pop("index", None)
            data = json.dumps({**envelope, "object": "chat.completion", "choices": [{"index": 0,
                "message": delta, "finish_reason": finish}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        encoded = data.encode()
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return server, thread


def main(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {"status": "incomplete", "scope": "Native OpenClaw exec in the configured Yuanxingmu backend",
              "model": "Local scripted HTTP fixture; no LLM inference or paid API call",
              "uncovered": ["browser", "web tools", "message tools", "MCP", "OpenClaw native subagent spawning"],
              "runs": []}
    readiness = sandbox_available(bwrap=args.bwrap)
    save(output / "sandbox-readiness.json", readiness)
    if not readiness["available"]:
        result.update(status="sandbox_unavailable", readiness=readiness)
        save(output / "results.json", result)
        return 2
    node = args.node.resolve()
    package = args.openclaw_package.resolve()
    result["versions"] = {"openclaw": json.loads((package / "package.json").read_text())["version"],
        "node": subprocess.check_output([str(node), "--version"], text=True).strip()}
    if result["versions"]["openclaw"] != "2026.9.4":
        raise RuntimeError("This example is validated against OpenClaw 2026.9.4")
    core = output / "trusted-core"
    private_copy(REPO / "yuanxingmu", core / "yuanxingmu")
    plugin = output / "plugin"
    private_copy(SOURCE / "plugin", plugin)
    (output / "node_modules").mkdir()
    (output / "node_modules/openclaw").symlink_to(package, target_is_directory=True)
    workspace = output / "workspace"
    workspace.mkdir()
    shutil.copy2(SOURCE / "worker_scenario.py", workspace / "worker_scenario.py")
    (workspace / "calculation.py").write_text("def answer():\n    return 40\n")
    private_path = output / "host-private.txt"
    marker = "SYNTHETIC-PRIVATE-" + uuid.uuid4().hex
    private_path.write_text(marker)
    state = output / "openclaw-state"
    state.mkdir()
    (output / "host-home").mkdir()
    receiver, receiver_thread = start_server(Receiver)
    receiver.receipts = []
    model, model_thread = start_server(FixtureModel)
    model.fixture = {"phase": None, "issued": False, "command": None, "requests": []}
    receiver_port = receiver.server_address[1]
    save(workspace / "scenario-settings.json", {"host_private_path": str(private_path),
        "host_launcher_marker": str(output / "unconfined-import.txt"),
        "receiver_port": receiver_port, "host_network_namespace": os.readlink("/proc/self/ns/net")})
    resources = {"private": Resource(private_path, ("private",))}
    destinations = {name: Destination(f"http://127.0.0.1:{receiver_port}/{name}", labels,
        {"Authorization": "Bearer SYNTHETIC-HOST-CREDENTIAL"})
        for name, labels in (("public", ()), ("internal", ("private",)))}
    broker = None
    try:
        broker = Broker(output / "broker-state", resources, destinations)
        task_id = broker.create_task()
        workspace = broker.bind_workspace(task_id, workspace)
        socket_path = broker.serve(task_id, output / "task.sock")
        session_id = str(uuid.uuid4())
        for phase in ("private", "resume", "public"):
            if phase == "resume":
                # Reopen the real ledger and endpoint, then start a new CLI process
                # against the SAME native OpenClaw session and persisted workspace.
                broker.close()
                broker = Broker(output / "broker-state", resources, destinations)
                workspace = broker.bind_workspace(task_id, workspace)
                socket_path = broker.serve(task_id, output / "task.sock")
            elif phase == "public":
                clean_task = broker.create_task()
                # A clean task must never inherit a private task's writable files.
                # The broker persistently rejects rebinding the previous workspace.
                workspace = output / "public-workspace"
                workspace.mkdir()
                shutil.copy2(SOURCE / "worker_scenario.py", workspace / "worker_scenario.py")
                save(workspace / "scenario-settings.json", {})
                workspace = broker.bind_workspace(clean_task, workspace)
                socket_path = broker.serve(clean_task, output / "clean.sock")
                session_id = str(uuid.uuid4())
            config = {"agents": {"defaults": {"workspace": str(workspace), "skipBootstrap": True,
                "model": {"primary": "fixture/synthetic-exec"}, "sandbox": {"mode": "all",
                "backend": "yuanxingmu", "scope": "session", "workspaceAccess": "rw",
                "docker": {"workdir": "/workspace"}, "browser": {"enabled": False}}}},
                "models": {"mode": "replace", "providers": {"fixture": {
                    "baseUrl": f"http://127.0.0.1:{model.server_address[1]}/v1", "apiKey": "synthetic-fixture-key",
                    "api": "openai-completions", "models": [{"id": "synthetic-exec", "name": "Synthetic fixture",
                    "input": ["text"], "reasoning": False, "contextWindow": 64000, "maxTokens": 2048,
                    "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}]}}},
                "tools": {"allow": ["exec"], "elevated": {"enabled": False},
                          "codeMode": {"enabled": False}, "exec": {"host": "sandbox", "timeoutSeconds": 25}},
                "plugins": {"allow": ["yuanxingmu"], "load": {"paths": [str(plugin)]},
                    "entries": {"yuanxingmu": {"enabled": True, "config": {
                        "python": "/usr/bin/python3", "corePath": str(core), "workspace": str(workspace),
                        "brokerSocket": str(socket_path), "bwrap": str(args.bwrap.resolve()),
                        "auditPath": str(output / "adapter-events.jsonl")}}}}}
            config_path = output / "openclaw.json"
            save(config_path, config)
            save(output / (phase + "-config.json"), config)
            environment = {"PATH": str(node.parent) + ":/usr/bin:/bin", "HOME": str(output / "host-home"),
                "LANG": "C.UTF-8", "OPENCLAW_STATE_DIR": str(state), "OPENCLAW_CONFIG_PATH": str(config_path),
                "OPENCLAW_SKIP_CHANNELS": "1", "OPENCLAW_SKIP_GMAIL_WATCHER": "1", "OPENCLAW_SKIP_CRON": "1",
                "OPENCLAW_SKIP_BROWSER_CONTROL_SERVER": "1", "OPENCLAW_SKIP_CANVAS_HOST": "1",
                "YUANXINGMU_HOST_SECRET": "SYNTHETIC-HOST-CREDENTIAL"}
            model.fixture.update(phase=phase, issued=False, command="python3 /workspace/worker_scenario.py " + phase)
            command = [str(node), str(package / "openclaw.mjs"), "agent", "--local", "--agent", "main",
                       "--session-id", session_id, "--message", "Run the synthetic local execution fixture.",
                       "--timeout", "90", "--json"]
            start = time.monotonic()
            with (output / (phase + ".stdout.log")).open("wb") as out, (output / (phase + ".stderr.log")).open("wb") as err:
                process = subprocess.run(command, env=environment, cwd=workspace, stdout=out, stderr=err, timeout=120)
            record = {"phase": phase, "command": command, "returncode": process.returncode,
                      "seconds": round(time.monotonic() - start, 3), "native_session_id": session_id,
                      "workspace": str(workspace)}
            result["runs"].append(record)
            save(output / "model-requests.json", model.fixture["requests"])
            scenario_path = workspace / (phase + "-result.json")
            if process.returncode != 0 or not scenario_path.exists():
                result["status"] = "native_execution_incomplete"
                break
            scenario = json.loads(scenario_path.read_text())
            record["scenario"] = scenario
            if not all(scenario["checks"].values()):
                result["status"] = "scenario_failed"
                break
        else:
            resumed_requests = [item for item in model.fixture["requests"] if item["phase"] == "resume"]
            result["native_restored_history_contains_private_marker"] = bool(resumed_requests) and marker in json.dumps(resumed_requests[0]["body"])
            result["receiver_checks"] = {
                "exactly_one_internal_private_delivery": len([item for item in receiver.receipts
                    if item["path"] == "/internal" and item["payload"]["body"] == marker]) == 1,
                "no_public_private_delivery": not any(item["path"] == "/public" and item["payload"]["body"] != "Synthetic public release"
                    for item in receiver.receipts),
                "one_public_clean_delivery": len([item for item in receiver.receipts if item["path"] == "/public"]) == 1,
                "host_credential_injected_only_by_broker": all(item["authorization"] == "Bearer SYNTHETIC-HOST-CREDENTIAL" for item in receiver.receipts),
            }
            result["launcher_checks"] = {"workspace_python_module_not_imported_on_host":
                                          not (output / "unconfined-import.txt").exists()}
            result["status"] = "observed_with_real_native_exec" if all(result["receiver_checks"].values()) and all(result["launcher_checks"].values()) and result["native_restored_history_contains_private_marker"] else "evidence_incomplete"
        result["authority_events"] = broker.authority.events(task_id)
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if broker is not None:
            broker.close()
        for server, thread in ((receiver, receiver_thread), (model, model_thread)):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        result["receipts"] = receiver.receipts
        result["source_hashes"] = {str(path.relative_to(core)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in sorted(core.rglob("*.py"))}
        save(output / "model-requests.json", model.fixture["requests"])
        save(output / "results.json", result)
    print(json.dumps({"status": result["status"], "runs": len(result["runs"]), "error": result.get("error"), "output": str(output)}))
    return 0 if result["status"] == "observed_with_real_native_exec" else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--openclaw-package", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
