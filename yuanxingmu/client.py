"""Small client usable inside the isolated worker; it holds no credential."""
from __future__ import annotations

import json
import os
import socket

MAX_MESSAGE = 1024 * 1024


def request(operation: str, *, socket_path: str | None = None, timeout_seconds: float = 15, **fields) -> dict:
    if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 120:
        raise ValueError("invalid_socket_timeout")
    path = socket_path or os.environ.get("YUANXINGMU_BROKER_SOCKET", "/run/yuanxingmu/broker.sock")
    payload = json.dumps({"op": operation, **fields}, ensure_ascii=True).encode() + b"\n"
    if len(payload) > MAX_MESSAGE:
        raise ValueError("request_too_large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout_seconds)
        connection.connect(path)
        connection.sendall(payload)
        with connection.makefile("rb") as stream:
            response = stream.readline(MAX_MESSAGE + 1)
    if not response.endswith(b"\n") or len(response) > MAX_MESSAGE:
        raise RuntimeError("broker_response_missing_or_too_large")
    return json.loads(response)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Use the current task's fixed broker endpoint")
    parser.add_argument("operation", choices=("read", "send", "describe"))
    parser.add_argument("identifier", nargs="?")
    parser.add_argument("--body", default="")
    args = parser.parse_args()
    fields = {}
    if args.operation == "read":
        fields["resource"] = args.identifier
    elif args.operation == "send":
        fields.update(destination=args.identifier, body=args.body)
    response = request(args.operation, **fields)
    print(json.dumps(response, ensure_ascii=True))
    if not response.get("allowed"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
