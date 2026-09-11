from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .config import ConfigurationError, Endpoint, inspect_config


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check whether selected MCP tools share a defense boundary")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read configuration without starting servers or calling tools")
    inspect.add_argument("config", type=Path)
    inspect.add_argument("--source", required=True, metavar="SERVER:TOOL")
    inspect.add_argument("--sink", required=True, metavar="SERVER:TOOL")
    plan = sub.add_parser("plan", help="Generate an unverified candidate for the supported rule; do not deploy it")
    plan.add_argument("config", type=Path)
    plan.add_argument("--source", required=True, metavar="SERVER:TOOL")
    plan.add_argument("--sink", required=True, metavar="SERVER:TOOL")
    plan.add_argument("--policy", required=True, type=Path)
    plan.add_argument("--allowed-domain", required=True)
    plan.add_argument("--aggregation-python", required=True, type=Path)
    plan.add_argument("--target-project", required=True)
    plan.add_argument("--output", required=True, type=Path)
    demo = sub.add_parser("demo", help="Run real installed runtimes with two independent synthetic MCP services")
    demo.add_argument("--gateway-python", required=True, type=Path)
    demo.add_argument("--aggregation-python", required=True, type=Path)
    demo.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            result = inspect_config(args.config, Endpoint.parse(args.source), Endpoint.parse(args.sink))
        elif args.command == "plan":
            from .plan import prepare_plan
            result = prepare_plan(args.config, Endpoint.parse(args.source), Endpoint.parse(args.sink), args.policy,
                args.allowed_domain, args.aggregation_python, args.target_project, args.output)
        else:
            from .demo import run_demo
            result = run_demo(args.output, args.gateway_python, args.aggregation_python)
            print(json.dumps({"status": result["status"], "counts": result.get("counts"),
                "evidence": str(args.output.resolve() / "results.json")}, ensure_ascii=False, indent=2))
            return 0 if result["status"] == "verified_for_demo_contract" else 1
    except (ConfigurationError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc), "security_result": "not_tested"}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
