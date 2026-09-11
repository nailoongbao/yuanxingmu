"""Demo-only loopback API adapter backed by the actual Invariant LocalPolicy.

This is not the official hosted rule service. Rules must be the generated,
event-binding template used by the demo; this is not a general policy server.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlparse


def serve(rules_path: Path, ledger: Path, token: str) -> None:
    from invariant.analyzer import LocalPolicy
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    engines = {name: LocalPolicy.from_string(rule) for name, rule in rules.items()}
    lock = threading.Lock()

    def record(event):
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, body, status=200):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

        def authorized(self):
            if self.headers.get("Authorization") != "Bearer " + token:
                self.reply({"error": "Invalid synthetic service token"}, 401)
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            path = urlparse(self.path).path
            if path == "/api/v1/user/identity":
                return self.reply({"username": "fixture"})
            prefix = "/api/v1/dataset/byuser/fixture/"
            if path.startswith(prefix) and path.endswith("/policy"):
                dataset = path[len(prefix):-len("/policy")]
                if dataset in rules:
                    return self.reply({"policies": [{"id": dataset, "name": "private-read-external-send",
                        "content": rules[dataset], "action": "block", "enabled": True}]})
            return self.reply({"error": "Unknown test route"}, 404)

        def do_POST(self):
            if not self.authorized():
                return
            if self.path != "/api/v1/policy/check/batch":
                return self.reply({"error": "Unknown test route"}, 404)
            payload = {}
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1_000_000:
                    return self.reply({"error": "Unsupported test request size"}, 413)
                payload = json.loads(self.rfile.read(length))
                dataset, messages = payload["dataset_name"], payload["messages"]
                if payload["policies"] != [rules[dataset]]:
                    raise ValueError("The gateway did not load the declared complete test rule")
                with lock:
                    analysis = engines[dataset].analyze_pending(messages[:-1], messages[-1:]).to_dict()
                    self.reply({"result": [analysis]})
                    record({"event": "policy_analysis", "http_status": 200, "dataset": dataset,
                        "session": payload.get("parameters", {}).get("metadata", {}).get("session_id"),
                        "messages": messages, "analysis": analysis})
            except Exception as exc:
                with lock:
                    record({"event": "policy_error", "http_status": 500,
                        "dataset": payload.get("dataset_name"), "messages": payload.get("messages", []),
                        "session": payload.get("parameters", {}).get("metadata", {}).get("session_id"),
                        "error": type(exc).__name__})
                return self.reply({"error": type(exc).__name__}, 500)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    # Finish request evidence before the parent reconciles the final policy ledger.
    server.daemon_threads = False
    print(json.dumps({"url": "http://127.0.0.1:" + str(server.server_address[1])}), flush=True)
    # The trusted demo parent controls lifetime over stdin, independently of HTTP.
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        sys.stdin.read()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("token")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    serve(args.rules, args.ledger, args.token)
