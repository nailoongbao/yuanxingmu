"""Two independent synthetic MCP services used only by the local demo."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


def serve(role: str, ledger: Path, marker: str) -> None:
    def record(event, **values):
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"event": event, "role": role, "pid": os.getpid(), **values}) + "\n")
    record("started")
    tool_name = "get_inbox" if role == "read" else "send_email"
    properties = {} if role == "read" else {k: {"type": "string"} for k in ("to", "subject", "body")}
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if "id" not in request:
                continue
            method = request.get("method")
            error = None
            if method == "initialize":
                result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "defensecheck-fixture-" + role, "version": "1"}}
            elif method == "tools/list":
                result = {"tools": [{"name": tool_name, "description": "Synthetic local test data only",
                    "inputSchema": {"type": "object", "properties": properties,
                                    "required": list(properties), "additionalProperties": False}}]}
            elif method == "tools/call" and request["params"]["name"] == tool_name:
                arguments = request["params"].get("arguments", {})
                record("tool_received", tool=tool_name, arguments=arguments)
                result = {"content": [{"type": "text", "text": marker if role == "read" else "LOCAL_RECEIPT"}], "isError": False}
            elif method == "ping":
                result = {}
            else:
                error = {"code": -32601, "message": "Unsupported fixture method or tool"}
            response = {"jsonrpc": "2.0", "id": request["id"]}
            response["error" if error else "result"] = error or result
            print(json.dumps(response), flush=True)
    finally:
        record("stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("read", "write"))
    parser.add_argument("ledger", type=Path)
    parser.add_argument("marker")
    options = parser.parse_args()
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    serve(options.role, options.ledger, options.marker)
