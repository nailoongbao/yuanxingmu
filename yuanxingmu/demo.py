"""Exercise real isolated processes against an independent synthetic receiver."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

from .broker import Broker, Destination, Resource
from .sandbox import sandbox_available
from .worker import start, stop


def run_demo(output: Path, *, bwrap: Path | None = None) -> dict:
    capability = sandbox_available(bwrap=bwrap)
    if not capability["available"]:
        raise RuntimeError("Linux isolation is unavailable: " + capability["reason"])
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    package = Path(__file__).resolve().parent
    source_root = package.parent
    secret = output / "private.txt"
    secret.write_text("SYNTHETIC-INTERNAL-ORDER-9471", encoding="utf-8")
    public = output / "public.txt"
    public.write_text("Public release notes", encoding="utf-8")
    receiver_file = output / "receiver.jsonl"
    receiver = subprocess.Popen([sys.executable, "-m", "yuanxingmu.receipts", "--output", str(receiver_file)],
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(source_root), "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, close_fds=True)
    runs = []
    report = {"schema": 1, "system": "Yuanxingmu", "status": "incomplete", "platform": platform.platform(),
              "python": platform.python_version(), "sandbox": capability,
              "scope": "Synthetic Python workers; real Linux isolation, SQLite and independent HTTP receipts. No model attack evaluation.",
              "runs": runs}
    broker = None
    processes = []
    try:
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(receiver.stdout, selectors.EVENT_READ)
            if not selector.select(10):
                raise RuntimeError("receiver_start_timeout")
        ready = json.loads(receiver.stdout.readline())
        port = ready["port"]
        report["receiver_pid"] = ready["pid"]
        resources = {"private": Resource(secret, ("internal",)), "public": Resource(public)}
        destinations = {"internal": Destination(f"http://127.0.0.1:{port}/internal", ("internal",)),
                        "public": Destination(f"http://127.0.0.1:{port}/public")}

        with tempfile.TemporaryDirectory(prefix="yxm-") as socket_root:
            socket_root = Path(socket_root)
            broker = Broker(output / "authority", resources, destinations)
            task = broker.create_task()
            child = broker.delegate(task, resources=[], destinations=["internal", "public"])
            clean = broker.create_task()
            report["tasks"] = {"root": task, "child_before_read": child, "clean": clean}
            endpoints = {name: broker.serve(value, socket_root / (name + ".sock")) for name, value in report["tasks"].items()}
            workspaces = {name: output / ("workspace-" + name) for name in endpoints}
            for path in workspaces.values():
                path.mkdir()
            for name, path in workspaces.items():
                broker.bind_workspace(report["tasks"][name], path)

            def worker(name, endpoint_name, script, *, raw=False):
                header = "import json, os, socket, base64, subprocess, sys\nfrom pathlib import Path\nfrom yuanxingmu.client import request\n"
                filename = workspaces[endpoint_name] / (name + ".py")
                filename.write_text(header + script, encoding="utf-8")
                proc = start(command=["/usr/bin/python3", "/workspace/" + filename.name],
                    workspace=workspaces[endpoint_name], broker_socket=endpoints[endpoint_name],
                    readonly_paths=[package], env={"PYTHONPATH": str(source_root)}, bwrap=bwrap,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    stop(proc)
                    raise RuntimeError("worker_timeout:" + name)
                item = {"name": name, "pid": proc.pid, "returncode": proc.returncode,
                        "exited": proc.poll() is not None, "stdout": stdout, "stderr": stderr}
                runs.append(item)
                if proc.returncode:
                    raise RuntimeError("worker_failed:" + name)
                return json.loads(stdout) if not raw else stdout

            checks = {}
            first = worker("read_and_send", "root", """
read = request('read', resource='private')
assert read['allowed']
Path('/workspace/saved.txt').write_text(read['content'])
denied = request('send', destination='public', body=read['content'])
encoded = request('send', destination='public', body=base64.b64encode(read['content'].encode()).decode())
summary = request('send', destination='public', body='This is harmless public text')
internal = request('send', destination='internal', body=read['content'])
print(json.dumps({'read': read['allowed'], 'plain': denied, 'encoded': encoded, 'public_summary': summary, 'internal': internal}))
""")
            checks["private_export_denied"] = first["plain"]["allowed"] is False
            checks["encoded_export_denied"] = first["encoded"]["allowed"] is False
            checks["internal_send_acknowledged"] = first["internal"].get("outcome") == "acknowledged"
            report["observed_business_cost"] = {"public_text_after_private_read_blocked": not first["public_summary"]["allowed"],
                "explanation": "Task-wide labels conservatively block even harmless public summaries after private reads; no automatic declassification."}
            child_result = worker("existing_child", "child_before_read", """
denied = request('send', destination='public', body='child tries a new process')
internal = request('send', destination='internal', body='child internal correction')
print(json.dumps({'denied': denied, 'internal': internal}))
""")
            checks["existing_child_inherits_read"] = child_result["denied"]["allowed"] is False
            checks["child_internal_send_acknowledged"] = child_result["internal"].get("outcome") == "acknowledged"
            bypass = worker("direct_bypass", "root", f"""
out = {{}}
try:
    socket.create_connection(('127.0.0.1', {port}), timeout=2).close()
    out['direct_network_denied'] = False
except OSError:
    out['direct_network_denied'] = True
try:
    Path({str(secret)!r}).read_text()
    out['host_resource_hidden'] = False
except OSError:
    out['host_resource_hidden'] = True
try:
    Path({str(output / 'authority' / 'authority.sqlite3')!r}).read_bytes()
    out['authority_hidden'] = False
except OSError:
    out['authority_hidden'] = True
out['identity_field_rejected'] = not request('send', destination='public', body='switch', task_id={clean!r})['allowed']
out['arbitrary_url_rejected'] = not request('send', destination='public', body='url', url='http://127.0.0.1:{port}/public')['allowed']
out['worker_cannot_create_root'] = not request('create_task')['allowed']
out['worker_cannot_clear_labels'] = not request('clear')['allowed']
Path('/workspace/normal.txt').write_text('normal work succeeds')
out['workspace_write_works'] = Path('/workspace/normal.txt').read_text() == 'normal work succeeds'
out['hostname_namespace'] = Path('/proc/self/status').read_text().split('NSpid:')[-1].splitlines()[0].strip()
print(json.dumps(out))
""")
            checks.update({k: v for k, v in bypass.items() if isinstance(v, bool)})
            # Reopen the real broker and database, keep the saved task and workspace.
            broker.close()
            broker = Broker(output / "authority", resources, destinations)
            endpoints = {name: broker.serve(value, socket_root / (name + ".sock")) for name, value in report["tasks"].items()}
            restored = worker("broker_restart", "root", """
body = Path('/workspace/saved.txt').read_text()
print(json.dumps(request('send', destination='public', body=body)))
""")
            checks["broker_restart_preserves_restriction"] = restored["allowed"] is False
            clean_result = worker("independent_public", "clean", """
read = request('read', resource='public')
assert read['allowed']
print(json.dumps(request('send', destination='public', body=read['content'])))
""")
            checks["independent_public_task_works"] = clean_result.get("outcome") == "acknowledged"
            broker.revoke(task)
            revoked = worker("revoked_task", "child_before_read", "print(json.dumps(request('send', destination='internal', body='revoked child')))\n")
            checks["revocation_reaches_child"] = revoked["allowed"] is False
            broker.close()
            broker = None
            # Mounting a stale/deleted endpoint must not yield an unsandboxed fallback.
            try:
                start(command=["/usr/bin/true"], workspace=workspaces["root"], broker_socket=endpoints["root"], bwrap=bwrap)
            except (RuntimeError, ValueError, FileNotFoundError):
                checks["missing_broker_fails_closed"] = True
            else:
                checks["missing_broker_fails_closed"] = False
            receipts = [json.loads(line) for line in receiver_file.read_text().splitlines()]
            checks["receiver_exactly_three_expected_receipts"] = len(receipts) == 3 and [r["receiver"] for r in receipts] == ["/internal", "/internal", "/public"]
            checks["public_receiver_only_public_content"] = [r["body"] for r in receipts if r["receiver"] == "/public"] == ["Public release notes"]
            report.update(checks=checks, receipts=receipts, status="passed" if all(checks.values()) else "failed")
    finally:
        if broker is not None:
            broker.close()
        for process in processes:
            stop(process)
        stop(receiver)
        report["all_workers_exited"] = all(p.poll() is not None for p in processes)
        report["receiver_exited"] = receiver.poll() is not None
        report["source_sha256"] = {str(path.relative_to(source_root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in package.glob("*.py")}
        (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
