"""Host CLI. Worker-facing operations are in yuanxingmu.client."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(prog="yuanxingmu", description="Yuanxingmu / 元星木 — authority outside the agent")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Check actual Linux isolation availability")
    doctor.add_argument("--bwrap", type=Path)
    demo = commands.add_parser("demo", help="Run isolated synthetic workers and verify independent receipts")
    demo.add_argument("--output", required=True, type=Path)
    demo.add_argument("--bwrap", type=Path)
    run = commands.add_parser("run", help="Run a command with a persistent task and operator-owned policy")
    run.add_argument("--policy", required=True, type=Path)
    run.add_argument("--state", required=True, type=Path)
    run.add_argument("--task", required=True)
    run.add_argument("--new-task", action="store_true", help="Explicitly create a trusted new root; omit when resuming")
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--bwrap", type=Path)
    run.add_argument("worker_command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command == "run":
            from .run import run_command
            command = args.worker_command[1:] if args.worker_command[:1] == ["--"] else args.worker_command
            if not command:
                parser.error("run requires a worker command after --")
            return run_command(policy=args.policy, state=args.state, task=args.task, new_task=args.new_task,
                               workspace=args.workspace, command=command, bwrap=args.bwrap)
        if args.command == "doctor":
            from .sandbox import sandbox_available
            result = sandbox_available(bwrap=args.bwrap)
            print(json.dumps(result, indent=2))
            return 0 if result["available"] else 2
        from .demo import run_demo
        result = run_demo(args.output, bwrap=args.bwrap)
        print(json.dumps({"status": result["status"], "checks": result.get("checks"), "output": str(args.output.resolve())}, indent=2))
        return 0 if result["status"] == "passed" else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
