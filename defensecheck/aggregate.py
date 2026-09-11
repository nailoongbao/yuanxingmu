"""Expose configured stdio services through one official FastMCP proxy.

The caller supplies the expected, already-namespaced tool names. All must be
available before the proxy starts serving its own stdio connection. One launcher
process belongs to one frontend connection; do not share it between users.
"""
from __future__ import annotations

import argparse
import asyncio
from importlib.metadata import version
import json
from pathlib import Path
import sys


PINNED_FASTMCP = "4.0.3"


async def serve(config_path: Path, required_tools: list[str]) -> None:
    from fastmcp import Client
    from fastmcp.server import create_proxy

    if version("fastmcp-slim") != PINNED_FASTMCP:
        raise RuntimeError(f"This launcher requires fastmcp-slim {PINNED_FASTMCP}")
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    # MCPConfig forwards each server's command, args, env and cwd unchanged.
    # Keep the connected client alive for this single frontend's entire lifetime.
    async with Client(config, mode="legacy", timeout=20.0) as backends:
        discovered = [tool.name for tool in await backends.list_tools()]
        if len(discovered) != len(set(discovered)):
            raise RuntimeError("Configured services expose duplicate tool names")
        missing = sorted(set(required_tools) - set(discovered))
        if missing:
            raise RuntimeError("Required tools unavailable: " + ", ".join(missing))
        proxy = create_proxy(backends, name="Configured MCP services")
        await proxy.run_async(transport="stdio", show_banner=False, log_level="WARNING")
    # Exiting Client's context closes the aggregate and its child transports.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="Path to standard mcpServers JSON")
    parser.add_argument("--require-tool", action="append", required=True,
                        help="Expected exposed tool name; repeat for every required tool")
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.config.resolve(), args.require_tool))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"MCP aggregation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
