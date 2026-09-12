"""Start a command behind an already-authorized broker endpoint (trusted host CLI)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess

from .sandbox import build_command


def start(*, command: list[str], workspace: Path, broker_socket: Path, readonly_paths=None,
          env=None, bwrap: Path | None = None, model_socket: Path | None = None, **popen_options):
    argv = build_command(command=command, workspace=workspace, broker_socket=broker_socket,
                         readonly_paths=readonly_paths, env=env, bwrap=bwrap, model_socket=model_socket)
    return subprocess.Popen(argv, env={"PATH": "/usr/bin:/bin"}, start_new_session=True,
                            close_fds=True, **popen_options)


def stop(process) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a worker with no direct network or host home access")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--broker-socket", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path)
    parser.add_argument("--readonly", action="append", default=[], type=Path)
    parser.add_argument("--env-json", default="{}")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command after -- is required")
    env = json.loads(args.env_json)
    process = start(command=command, workspace=args.workspace, broker_socket=args.broker_socket,
                    readonly_paths=args.readonly, env=env, bwrap=args.bwrap)

    def interrupted(signum, frame):
        stop(process)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(process.wait())
    finally:
        stop(process)


if __name__ == "__main__":
    main()
