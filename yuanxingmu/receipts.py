"""Independent loopback-only receiver for synthetic demos. Never a production sink."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import hashlib
import json
import os
from pathlib import Path
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    lock = threading.Lock()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.touch(exist_ok=False)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024 * 1024:
                self.send_error(413)
                return
            value = json.loads(self.rfile.read(length))
            entry = {"receiver": self.path, "request_id": value["request_id"],
                     "body_sha256": hashlib.sha256(value["body"].encode()).hexdigest(),
                     "body": value["body"]}
            with lock:
                with args.output.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    print(json.dumps({"port": server.server_port, "pid": os.getpid()}), flush=True)
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
