"""Host CLI. Worker-facing operations are in yuanxingmu.client."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(prog="yuanxingmu", description="Yuanxingmu / 元星木 — authority outside the agent")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Check actual Linux isolation availability")
    doctor.add_argument("--bwrap", type=Path)
    demo = commands.add_parser("demo", help="Run isolated synthetic workers and verify independent receipts")
    demo.add_argument("--output", required=True, type=Path)
    demo.add_argument("--bwrap", type=Path)
    desk = commands.add_parser("desk", help="打开元星木本地工作台，在页面中导入资料和管理 OpenClaw")
    desk.add_argument("--install-root", type=Path, default=Path.home() / "yuanxingmu")
    desk.add_argument("--data", type=Path, help="工作台自己的新目录；默认是安装目录下的 workbench")
    desk.add_argument("--port", type=int, default=18910)
    desk.add_argument("--node", type=Path)
    desk.add_argument("--openclaw-package", type=Path)
    desk.add_argument("--bwrap", type=Path)
    desk.add_argument("--no-browser", action="store_true")
    run = commands.add_parser("run", help="Run a command with a persistent task and operator-owned policy")
    run.add_argument("--policy", required=True, type=Path)
    run.add_argument("--state", required=True, type=Path)
    run.add_argument("--task", required=True)
    run.add_argument("--new-task", action="store_true", help="Explicitly create a trusted new root; omit when resuming")
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--bwrap", type=Path)
    run.add_argument("worker_command", nargs=argparse.REMAINDER)
    openclaw = commands.add_parser("openclaw", help="创建和使用受保护的 OpenClaw")
    actions = openclaw.add_subparsers(dest="action", required=True)
    init = actions.add_parser("init", help="连接自己的模型，建立独立实例")
    init.add_argument("--profile", required=True, type=Path)
    init.add_argument("--model-url", required=True, help="OpenAI-compatible endpoint, including /v1")
    init.add_argument("--model-id", required=True)
    init.add_argument("--api-key-env", help="从指定环境变量读取模型密钥；不传密钥值到命令行")
    init.add_argument("--document", action="append", default=[], metavar="NAME=PATH", help="导入 UTF-8 文本快照；可重复")
    init.add_argument("--destinations", type=Path, help="操作者选择的固定接收位置 JSON 文件；默认不能发送")
    init.add_argument("--node", type=Path)
    init.add_argument("--openclaw-package", type=Path)
    init.add_argument("--bwrap", type=Path)
    init.add_argument("--port", type=int, default=18911)
    init.add_argument("--context-window", type=int, default=32768)
    init.add_argument("--max-tokens", type=int, default=2048)
    for name, help_text in (("start", "启动或重新打开原来的实例"), ("status", "查看模型、资料与权限状态"),
                            ("revoke", "永久收回这个实例的资料读取和发送权限"), ("stop", "关闭本实例及其运行中的命令")):
        action = actions.add_parser(name, help=help_text)
        action.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "desk":
            from .dashboard.server import Runtime, serve
            install_root = args.install_root.expanduser()
            runtime = Runtime.discover(install_root, node=args.node, openclaw_package=args.openclaw_package, bwrap=args.bwrap)
            return serve(args.data or install_root / "workbench", runtime, port=args.port, open_browser=not args.no_browser)
        if args.command == "openclaw":
            from .openclaw import init_profile, start_profile, control_profile
            if args.action == "init":
                documents = {}
                for item in args.document:
                    name, separator, path = item.partition("=")
                    if not separator or not path or name in documents:
                        raise ValueError("--document 需要不重复的 NAME=PATH")
                    documents[name] = Path(path).expanduser()
                key = "local-unused"
                if args.api_key_env:
                    key = os.environ.get(args.api_key_env, "")
                    if not key:
                        raise ValueError("指定的模型密钥环境变量不存在或为空。")
                elif args.model_url.startswith("https:"):
                    if not sys.stdin.isatty():
                        raise ValueError("请用 --api-key-env 指定保存模型密钥的环境变量。")
                    from getpass import getpass
                    key = getpass("模型 API 密钥（输入不会显示）：")
                node = args.node or shutil.which("node")
                bwrap = args.bwrap or shutil.which("bwrap")
                package = args.openclaw_package
                if not package:
                    executable = shutil.which("openclaw")
                    package = Path(executable).resolve().parent if executable else None
                if not node or not bwrap or not package:
                    raise RuntimeError("需要 Node.js、bubblewrap 和 OpenClaw 2026.9.4；也可用 --node / --bwrap / --openclaw-package 指定路径。")
                destinations = json.loads(args.destinations.read_text(encoding="utf-8")) if args.destinations else {}
                result = init_profile(args.profile.expanduser(), node=Path(node), bwrap=Path(bwrap), openclaw_package=Path(package),
                    model_url=args.model_url, model_id=args.model_id, api_key=key, documents=documents,
                    destinations=destinations, port=args.port, context_window=args.context_window, max_tokens=args.max_tokens)
            elif args.action == "start":
                result = start_profile(args.profile.expanduser())
            else:
                result = control_profile(args.profile.expanduser(), args.action)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
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
