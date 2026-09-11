"""Exercise a fresh real installation, including the native OpenClaw gateway.

Creates one synthetic work item. No model request or message send is performed.
Only the newly created item and this script's launcher process are stopped.
Management links stay in private logs and never enter the public report.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def smoke(root, report_path):
    os.umask(0o077)
    if (root / "workbench").exists() or (root / "workbench").is_symlink():
        raise RuntimeError("Use a fresh installation with no workbench; saved work is never adopted")
    if report_path.exists():
        raise RuntimeError("Preserve the existing acceptance report and choose a new path")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    checks, failures = [], []
    process = None
    token = identifier = None
    sequence = 0
    scenario_completed = False

    def check(name, passed):
        checks.append({"name": name, "passed": bool(passed)})
        if not passed:
            raise AssertionError(name)
        print("PASS " + name, flush=True)

    def request(path, value=None):
        headers = {"Authorization": "Bearer " + token, "Origin": origin}
        if value is not None:
            headers.update({"Content-Type": "application/json", "Idempotency-Key": uuid.uuid4().hex})
        req = urllib.request.Request(origin + path, headers=headers,
            data=json.dumps(value).encode() if value is not None else None)
        with opener.open(req, timeout=30) as response:
            return json.load(response)

    def launch():
        nonlocal process, token, sequence
        sequence += 1
        log_path = root / ("acceptance-launch-" + str(sequence) + ".log")
        with log_path.open("xb") as log:
            process = subprocess.Popen([str(root / "open-yuanxingmu"), "--no-browser", "--port", str(port)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            match = re.search(re.escape(origin) + r"/#access=([A-Za-z0-9_-]{32,128})", log_path.read_text())
            if match:
                token = match[1]
                return
            if process.poll() is not None:
                raise RuntimeError("Launcher exited before opening its management service; see private log")
            time.sleep(.2)
        raise TimeoutError("Launcher did not open its management service")

    def stop_launcher():
        nonlocal process, token
        if process is not None:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=45)
            check("launcher exits cleanly " + str(sequence), process.returncode == 0)
            process = None
            token = None

    def operation(path, value):
        accepted = request(path, value)["job"]
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            job = request("/api/jobs/" + accepted["id"])["job"]
            if job["status"] != "running":
                if job["status"] != "succeeded":
                    raise RuntimeError("Workbench operation failed: " + job["action"])
                return job
            time.sleep(.3)
        raise TimeoutError("Workbench operation did not complete")

    def native_page(job):
        url = urllib.parse.urlsplit(job["result"]["dashboard_url"])
        if url.scheme != "http" or url.hostname != "127.0.0.1":
            raise RuntimeError("Native gateway URL is not loopback")
        with opener.open(url._replace(fragment="").geturl(), timeout=15) as response:
            body = response.read()
            return response.status == 200 and b"openclaw" in body.lower()

    try:
        launch()
        check("installed runtime is available", request("/api/info")["runtime"]["available"] is True)
        check("new workbench has no saved work", request("/api/profiles")["profiles"] == [])
        with opener.open(origin, timeout=10) as response:
            check("real workbench page is served", response.status == 200 and "元星木".encode() in response.read())
        duplicate = subprocess.run([str(root / "open-yuanxingmu"), "--no-browser", "--port", str(port)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        check("duplicate launcher is refused", duplicate.returncode == 2 and "已经打开".encode() in duplicate.stderr)
        created = operation("/api/profiles", {"name": "安装检查 · 合成报价", "model_url": "http://127.0.0.1:19999/v1",
            "model_id": "acceptance-no-model-request", "api_key": "", "documents": [
                {"name": "quote", "filename": "quote.txt", "content": "仅供安装验收的合成资料：报价为 10000 元。"}]})
        identifier = created["profile_id"]
        prefix = "/api/profiles/" + identifier
        check("real OpenClaw profile is initialized", request("/api/profiles")["profiles"][0]["id"] == identifier)
        started = operation(prefix + "/start", {})
        check("native OpenClaw WebUI responds", native_page(started))
        operation(prefix + "/stop", {})
        check("native agent stops", request("/api/profiles")["profiles"][0]["status"] == "stopped")
        catalog = json.loads((root / "workbench/catalog.json").read_text())
        identity = {key: catalog[key] for key in ("root_identity", "profiles_identity", "imports_identity")}
        old_token = token
        stop_launcher()
        launch()
        old_request = urllib.request.Request(origin + "/api/info", headers={"Authorization": "Bearer " + old_token})
        try:
            with opener.open(old_request, timeout=10) as response:
                old_status = response.status
        except urllib.error.HTTPError as exc:
            old_status = exc.code
        check("previous management token is refused", old_status == 401)
        reopened = request("/api/profiles")["profiles"]
        check("same work survives reopening", len(reopened) == 1 and reopened[0]["id"] == identifier)
        catalog = json.loads((root / "workbench/catalog.json").read_text())
        check("workbench storage identity is preserved", all(catalog[key] == value for key, value in identity.items()))
        check("native WebUI reopens", native_page(operation(prefix + "/start", {})))
        operation(prefix + "/revoke", {"confirm": "revoke"})
        check("authority is revoked", request("/api/profiles")["profiles"][0]["revoked"] is True)
        operation(prefix + "/stop", {})
        final = request("/api/profiles")["profiles"][0]
        check("final native state is stopped and revoked", final["status"] == "stopped" and final["revoked"] is True)
        scenario_completed = True
    except BaseException as exc:
        failures.append(type(exc).__name__ + ": " + str(exc))
    finally:
        if identifier and token:
            try:
                state = request("/api/profiles")["profiles"][0]
                if state["revoked"] is not True:
                    operation("/api/profiles/" + identifier + "/revoke", {"confirm": "revoke"})
                if state["status"] != "stopped":
                    operation("/api/profiles/" + identifier + "/stop", {})
            except Exception as exc:
                failures.append("Cleanup of created profile: " + type(exc).__name__)
        try:
            stop_launcher()
        except Exception as exc:
            failures.append("Launcher cleanup: " + type(exc).__name__)
        if not scenario_completed and not failures:
            failures.append("Acceptance scenario did not finish")
        result = {"schema_version": 1, "time": datetime.now(timezone.utc).isoformat(),
            "passed": scenario_completed and not failures, "scenario_completed": scenario_completed,
            "scope": "Fresh installed launcher, actual OpenClaw initialization, native WebUI HTTP, duplicate refusal, reopen, revoke and stop; no model inference or message sending.",
            "checks": checks, "failures": failures}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("x") as output:
            json.dump(result, output, ensure_ascii=False, indent=2)
        print(json.dumps({"passed": result["passed"], "checks": len(checks), "failures": failures}), flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(smoke(args.install_root, args.report))
